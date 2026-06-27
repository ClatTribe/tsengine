package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// noopApplier lets approved actions "apply" without side effects.
type noopApplier struct{}

func (noopApplier) Apply(context.Context, platform.Action) error { return nil }

func setupLoop(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	// a pending (gated) action for the approvals test
	_ = st.PutAction(ctx, platform.Action{ID: "act1", TenantID: "t1", Tier: 2, Kind: platform.ActApplyConfig, Status: platform.ActPendingApproval})
	// a control gap for the posture test
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "t1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlGap})

	desk := &hitl.Desk{Store: st, Apply: noopApplier{}}
	g := &grc.GRC{Store: st}
	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(fakeConn{}), Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(fakeConn{}), Runner: svc, Desk: desk, GRC: g, Token: "platform-tok", PublicURL: "https://app"})
	return h, st
}

func TestApprovalDecide_HumanApproves(t *testing.T) {
	h, st := setupLoop(t)

	rec := do(h, "POST", "/v1/approvals/act1", "t1", `{"approver":"kanpur-analyst","approve":true,"edit":{"base":"release"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide: code %d body %s", rec.Code, rec.Body.String())
	}
	var act platform.Action
	_ = json.Unmarshal(rec.Body.Bytes(), &act)
	if act.Status != platform.ActApplied || act.Approver != "kanpur-analyst" {
		t.Errorf("approved action wrong: %+v", act)
	}
	// the queue is now empty
	got, _ := st.PendingApprovals(context.Background(), "t1")
	if len(got) != 0 {
		t.Errorf("approved action should leave the queue, %d left", len(got))
	}
}

func TestPostureEndpoint(t *testing.T) {
	h, _ := setupLoop(t)
	rec := do(h, "GET", "/v1/posture/soc2", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("posture: code %d", rec.Code)
	}
	var cs []platform.ControlState
	_ = json.Unmarshal(rec.Body.Bytes(), &cs)
	if len(cs) != 1 || cs[0].ControlID != "CC6.1" || cs[0].State != platform.ControlGap {
		t.Errorf("posture wrong: %+v", cs)
	}
}

// TestPostureSummaryEndpoint: the batched GET /v1/posture returns every TRACKED framework's
// summary in one call (only soc2 has control state here → one entry), omitting untracked
// frameworks, with a non-null frameworks array (the nil-slice→null guard).
func TestPostureSummaryEndpoint(t *testing.T) {
	h, _ := setupLoop(t)
	rec := do(h, "GET", "/v1/posture", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("posture summary: code %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), ":null") {
		t.Errorf("frameworks must serialize as [] not null: %s", rec.Body.String())
	}
	var out struct {
		Frameworks []struct {
			Framework       string `json:"framework"`
			Total, Met, Gap int
		} `json:"frameworks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Frameworks) != 1 {
		t.Fatalf("want only the 1 tracked framework, got %d: %s", len(out.Frameworks), rec.Body.String())
	}
	if f := out.Frameworks[0]; f.Framework != "soc2" || f.Total != 1 || f.Gap != 1 || f.Met != 0 {
		t.Errorf("soc2 summary wrong: %+v", f)
	}
}

func TestConnectURLCarriesTenantInState(t *testing.T) {
	h, _ := setupLoop(t)
	rec := do(h, "GET", "/v1/connect/github", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("connect url: code %d", rec.Code)
	}
	var body struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	// the OAuth state must carry the tenant — now as a SIGNED token "t1:<exp>:<hmac>" so the
	// (unauthenticated) callback can attribute it without trusting a raw, forgeable tenant id
	// (oauthstate.go). The fakeConn doesn't URL-encode, so the ":" is literal here.
	if !strings.Contains(body.AuthorizeURL, "state=t1:") || !strings.Contains(body.AuthorizeURL, "callback") {
		t.Errorf("authorize url missing signed tenant state / redirect: %s", body.AuthorizeURL)
	}
}

func TestPostureNotConfigured(t *testing.T) {
	// GRC omitted → 501, not a panic
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/posture/soc2", "t1", "")
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("missing GRC should be 501, got %d", rec.Code)
	}
}

func TestComplianceReport_UnknownFrameworkIs404(t *testing.T) {
	h, _ := setupLoop(t)
	// A valid framework reports (200).
	if rec := do(h, "GET", "/v1/compliance/soc2/report?format=json", "t1", ""); rec.Code != 200 {
		t.Fatalf("a tracked framework should report, got %d", rec.Code)
	}
	// An unknown framework must 404 — never a fabricated empty report titled with the bogus key.
	rec := do(h, "GET", "/v1/compliance/bogus/report?format=json", "t1", "")
	if rec.Code != 404 {
		t.Errorf("an unknown framework must 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "\"Framework\":\"bogus\"") {
		t.Error("must not render a report body for an unknown framework (grounding §10)")
	}
}
