// Package replay implements the tool-replay API — the "dig deeper"
// capability webappsec exposes to security engineers, and the route L2
// uses when it calls dispatch_l2_probe(tool=<registry>) (CLAUDE.md §9).
//
// Phase 2 implements the Replay function (used by both the CLI
// `tsengine replay` subcommand and tests) and an HTTPHandler that wraps
// it. The HTTP server binding lands in Phase 5 — the handler is unit
// tested here via httptest so the contract is locked.
package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Request is the wire shape of a /replay POST. Mirrors CLAUDE.md §9.
type Request struct {
	ScanID        string    `json:"scan_id"`
	Tool          string    `json:"tool"`
	Target        string    `json:"target,omitempty"`
	Args          tool.Args `json:"args,omitempty"`
	UseCorpusFrom string    `json:"use_corpus_from,omitempty"`
}

// Response is the wire shape of a successful /replay response.
type Response struct {
	ReplayID string          `json:"replay_id"`
	Findings []types.Finding `json:"findings"`
}

// Dispatcher is the minimal interface Replay needs from sandbox.Client.
// Tests inject mocks.
type Dispatcher interface {
	Execute(ctx context.Context, toolName string, args tool.Args) (tool.Result, error)
}

// Spawner produces a sandbox + dispatcher for a given image digest. The
// production impl spawns a real container; tests inject one that
// returns a mock dispatcher.
type Spawner interface {
	Spawn(ctx context.Context, imageDigest string) (Dispatcher, func(context.Context) error, error)
}

// Replay executes one tool against a (possibly overridden) target, with
// the sandbox image pinned to the original scan's image digest. It
// returns the new findings; it does NOT mutate the scan on disk —
// caller writes them back if it wants to extend the original.
func Replay(ctx context.Context, req Request, runsDir string, spawner Spawner) (*Response, error) {
	if err := validate(req); err != nil {
		return nil, err
	}

	original, err := loadScan(runsDir, req.ScanID)
	if err != nil {
		return nil, fmt.Errorf("replay: load scan %q: %w", req.ScanID, err)
	}

	target := req.Target
	if target == "" {
		target = original.Asset.Target
	}

	digest := original.Engine.SandboxImageDigest
	if digest == "" {
		return nil, errors.New("replay: original scan has no sandbox_image_digest pinned")
	}

	dispatcher, destroy, err := spawner.Spawn(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("replay: spawn sandbox at %s: %w", digest, err)
	}
	defer func() { _ = destroy(context.Background()) }()

	args := tool.Args{"target": target}
	for k, v := range req.Args {
		args[k] = v
	}

	result, err := dispatcher.Execute(ctx, req.Tool, args)
	if err != nil {
		return nil, fmt.Errorf("replay: execute %s: %w", req.Tool, err)
	}

	replayID := newReplayID()
	now := time.Now().UTC()

	emitted := append([]types.SandboxEmittedFinding(nil), result.Findings...)
	emitted = append(emitted, result.SandboxEmittedFindings...)

	findings := make([]types.Finding, 0, len(emitted))
	for i, e := range emitted {
		findings = append(findings, types.Finding{
			ID:              fmt.Sprintf("%s-r%04d", replayID, i+1),
			RuleID:          e.RuleID,
			Tool:            e.Tool,
			Severity:        e.Severity,
			CWE:             e.CWE,
			Endpoint:        e.Endpoint,
			Title:           e.Title,
			Description:     e.Description,
			RawOutput:       e.RawOutput,
			MITRETechniques: e.MITRETechniques,
			ToolArgs:        e.ToolArgs,
			DiscoveredAt:    now,
			DiscoveryMethod: &types.DiscoveryMethod{
				Primary:  "tool_replay",
				ReplayOf: replayID,
			},
		})
	}
	return &Response{ReplayID: replayID, Findings: findings}, nil
}

// HTTPHandler returns an http.HandlerFunc that serves POST /replay,
// suitable for mounting on the tsengine server (Phase 5).
func HTTPHandler(runsDir string, spawner Spawner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "decode: "+err.Error())
			return
		}
		resp, err := Replay(r.Context(), req, runsDir, spawner)
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, errNotFound) {
				code = http.StatusNotFound
			} else if errors.Is(err, errBadRequest) {
				code = http.StatusBadRequest
			}
			writeJSONErr(w, code, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// --- helpers ----------------------------------------------------

var (
	errBadRequest = errors.New("replay: bad request")
	errNotFound   = errors.New("replay: scan not found")
)

func validate(req Request) error {
	if req.ScanID == "" {
		return fmt.Errorf("%w: missing scan_id", errBadRequest)
	}
	if req.Tool == "" {
		return fmt.Errorf("%w: missing tool", errBadRequest)
	}
	return nil
}

// loadScan reads <runsDir>/<scanID>/vulnerabilities.json and decodes it
// as a Scan. The scan's corpus + image digest are used as the
// reproducibility pin (CLAUDE.md §10).
func loadScan(runsDir, scanID string) (*types.Scan, error) {
	p := filepath.Join(runsDir, scanID, "vulnerabilities.json")
	f, err := os.Open(p) //nolint:gosec // runsDir/scanID are operator-provided paths
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", errNotFound, scanID)
		}
		return nil, err
	}
	defer f.Close()
	var scan types.Scan
	if err := json.NewDecoder(f).Decode(&scan); err != nil {
		return nil, fmt.Errorf("replay: decode scan: %w", err)
	}
	return &scan, nil
}

// newReplayID is a short unique identifier for the replay batch. Used
// to tag findings with discovery_method.replay_of so they're auditable.
func newReplayID() string {
	return fmt.Sprintf("rpl-%d", time.Now().UTC().UnixNano())
}

func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// LiveSpawner is the production sandbox.Spawn-backed Spawner used by
// the CLI replay subcommand and the Phase 5 HTTP server.
type LiveSpawner struct {
	// Image fallback when the image digest isn't pullable as a ref. For
	// Phase 2/5 we expect the digest to be reachable from the local
	// docker daemon. If not, set Image to a tagged alias.
	Image string
}

// Spawn implements Spawner. Returns a sandbox.Client wrapper and the
// destroy callback.
func (l *LiveSpawner) Spawn(ctx context.Context, imageDigest string) (Dispatcher, func(context.Context) error, error) {
	image := imageDigest
	if l.Image != "" {
		image = l.Image
	}
	info, err := sandbox.Spawn(ctx, sandbox.SpawnOptions{Image: image})
	if err != nil {
		return nil, nil, err
	}
	client := sandbox.NewClient(info)
	destroy := func(ctx context.Context) error { return sandbox.Destroy(ctx, info) }
	return client, destroy, nil
}
