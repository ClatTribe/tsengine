package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// replayScanner records what it was asked to run, so the tests can assert the request actually
// reached the tool with the engineer's arguments.
type replayScanner struct {
	gotAsset platform.Asset
	gotTool  string
	gotArgs  tool.Args
	findings []types.Finding
	err      error
}

func (r *replayScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) { return nil, nil }
func (r *replayScanner) ReplayTool(_ context.Context, a platform.Asset, name string, args tool.Args, _ string) ([]types.Finding, error) {
	r.gotAsset, r.gotTool, r.gotArgs = a, name, args
	return r.findings, r.err
}

func replayDeps(sc runner.ScanRunner) (http.Handler, store.Store) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "web_application", Target: "https://mine.test/"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a2", TenantID: "victim", Type: "web_application", Target: "https://not-mine.test/"})
	h := NewHandler(Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		Runner: &runner.Service{Store: st, Scanner: sc},
		NewID:  func() string { return "rp1" },
	})
	return h, st
}

// THE security property. Replay points a scanner at a target, so resolving the asset by id alone —
// rather than from THIS tenant's assets — would let one tenant aim the engine at another's
// infrastructure. That is not a bug, it is an attack (§18.2 inv. 2).
func TestReplay_CannotReachAnotherTenantsAsset(t *testing.T) {
	sc := &replayScanner{}
	h, _ := replayDeps(sc)

	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"a2","tool":"nuclei"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant replay must 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if sc.gotTool != "" {
		t.Fatalf("the scanner was invoked for another tenant's asset (%q @ %q)", sc.gotTool, sc.gotAsset.Target)
	}
}

// The engineer's own arguments must reach the tool — that is the entire point of replay.
func TestReplay_PassesTheEngineersArgsAndOverride(t *testing.T) {
	sc := &replayScanner{findings: []types.Finding{{
		ID: "x", RuleID: "nuclei::custom", Tool: "nuclei", Severity: types.SeverityHigh, Endpoint: "https://mine.test/x",
	}}}
	h, _ := replayDeps(sc)

	rec := do(h, "POST", "/v1/replay", "t1",
		`{"asset_id":"a1","tool":"nuclei","target":"https://mine.test/deep","args":{"-t":"my-template.yaml"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if sc.gotTool != "nuclei" {
		t.Errorf("tool = %q, want nuclei", sc.gotTool)
	}
	if sc.gotArgs["-t"] != "my-template.yaml" {
		t.Errorf("the engineer's args did not reach the tool: %+v", sc.gotArgs)
	}
	if sc.gotAsset.Target != "https://mine.test/deep" {
		t.Errorf("target override ignored, got %q", sc.gotAsset.Target)
	}

	var resp replayResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Findings) != 1 || resp.ReplayID == "" {
		t.Errorf("expected the replay's findings and an id, got %+v", resp)
	}
	// A replay is an investigation: it must not silently enlarge the queue unless asked.
	if resp.Stored != 0 {
		t.Errorf("replay stored %d findings without store:true", resp.Stored)
	}
}

// An empty replay is a result about THOSE arguments, not a clean bill of health for the target —
// the same grounding discipline as coverage and the audit surface.
func TestReplay_EmptyResultIsScopedNotReassuring(t *testing.T) {
	h, _ := replayDeps(&replayScanner{})
	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"a1","tool":"nuclei"}`)
	var resp replayResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Note == "" || !strings.Contains(resp.Note, "does not clear the target") {
		t.Errorf("an empty replay must be scoped to its arguments, got note %q", resp.Note)
	}
}

// A runner with no tools to re-run must refuse honestly rather than return an empty success that
// reads as "the tool ran and found nothing".
func TestReplay_UnsupportedScannerRefusesHonestly(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutAsset(context.Background(), platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme.com"})
	h := NewHandler(Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		Runner: &runner.Service{Store: st, Scanner: plainScanner{}},
	})
	rec := do(h, "POST", "/v1/replay", "t1", `{"asset_id":"a1","tool":"nuclei"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 for a scanner that cannot replay, got %d: %s", rec.Code, rec.Body.String())
	}
}

type plainScanner struct{}

func (plainScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	return nil, errors.New("not used")
}
