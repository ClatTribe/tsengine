package platformapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// replay.go is the §9 tool-replay API on the PLATFORM — the security engineer's "dig deeper".
//
// It is the affordance that separates a tool a security engineer will trust from one they will not.
// Everywhere else the product decides which tools run and with what arguments; this is where a human
// overrides that: run nuclei with my template, run sqlmap with a tamper script, go and settle the
// question the agent left open. Practitioners are explicit that they trust AI output only as far as
// they can verify it, and verification means re-running the thing yourself.
//
// It existed in the engine CLI from Phase 5 and was never exposed on the platform, so the product's
// users — the ones who actually have a queue to work through — could only accept or reject what the
// AI chose to do.

type replayRequest struct {
	AssetID string    `json:"asset_id"`
	Tool    string    `json:"tool"`
	Target  string    `json:"target,omitempty"` // optional override (§9 permits re-pointing the tool)
	Args    tool.Args `json:"args,omitempty"`
	// Store, when true, persists the replay findings alongside the tenant's other findings. Default
	// false: a replay is an INVESTIGATION, and most of them should not permanently enlarge the queue
	// the engineer is trying to shrink. They opt in when the replay found something worth keeping.
	Store bool `json:"store,omitempty"`
}

type replayResponse struct {
	ReplayID string          `json:"replay_id"`
	Tool     string          `json:"tool"`
	Target   string          `json:"target"`
	Findings []types.Finding `json:"findings"`
	Stored   int             `json:"stored"`
	Note     string          `json:"note,omitempty"`
}

// handleReplay re-runs one tool with the engineer's own arguments against one of their assets.
func (d Deps) handleReplay(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req replayRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if strings.TrimSpace(req.Tool) == "" || strings.TrimSpace(req.AssetID) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("asset_id and tool are required"))
		return
	}
	if d.Runner == nil || d.Runner.Scanner == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("this deployment has no scanning engine wired, so a tool cannot be re-run"))
		return
	}
	replayer, ok := d.Runner.Scanner.(runner.ToolReplayer)
	if !ok {
		// Honest refusal rather than a silent no-op: the identity/operate runner assesses a posted
		// snapshot and has no tools to re-run at all.
		writeJSON(w, http.StatusServiceUnavailable, errBody("the configured scanner cannot re-run individual tools"))
		return
	}

	// Tenant scoping is the security boundary (§18.2 inv. 2): resolve the asset from THIS tenant's
	// assets, never from the id alone, or one tenant could aim a scanner at another's target.
	assets, err := d.Store.ListAssets(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var target *platform.Asset
	for i := range assets {
		if assets[i].ID == req.AssetID {
			a := assets[i]
			target = &a
			break
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, errBody("no such asset for this tenant"))
		return
	}
	if t := strings.TrimSpace(req.Target); t != "" {
		target.Target = t
	}

	replayID := d.newID("replay")
	findings, err := replayer.ReplayTool(r.Context(), *target, req.Tool, req.Args, replayID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		return
	}
	// Replay findings go through the same L1.5 chain as everything else, so what the engineer gets
	// back is comparable with the rest of the queue rather than a differently-shaped answer.
	findings = enrichFindings(findings) // one name for this call across the package (ADR 0029 D1b)

	resp := replayResponse{ReplayID: replayID, Tool: req.Tool, Target: target.Target, Findings: findings}
	if req.Store {
		// ADR 0029 D1a — the third door that enriched and never folded. "Investigate deeper" is the
		// action a security engineer takes on a finding they already suspect, so a finding it turns up
		// is one of the most likely to be real, and it opened no control gap.
		stored := make([]types.Finding, 0, len(findings))
		for _, f := range findings {
			if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
				continue
			}
			resp.Stored++
			stored = append(stored, f)
		}
		d.foldIntoPosture(r.Context(), tenantID, stored)
	}
	if len(findings) == 0 {
		resp.Note = fmt.Sprintf("%s ran and returned nothing. That is a result about these arguments only — "+
			"it does not clear the target generally.", req.Tool)
	}
	if d.Recorder != nil {
		d.Recorder.Record("tool replayed", "replay",
			map[string]any{"tenant_id": tenantID, "tool": req.Tool, "asset": req.AssetID, "findings": len(findings)},
			"security engineer re-ran a tool with custom arguments (§9)")
	}
	writeJSON(w, http.StatusOK, resp)
}
