package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A ScubaGear document we cannot read must come back as unreadable, never as a tenant with nothing
// wrong. This is the direction of the error that matters: silence here would turn our inability to
// parse CISA's output into a clean bill of health.
func TestScubaIngest_UnreadableDocumentIsRejectedNotReportedClean(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	rec := do(h, "POST", "/v1/scuba/ingest", "t1", `{"metadata":{"tenant":"acme"}}`)
	if rec.Code != 400 {
		t.Fatalf("want 400 for an unrecognized document, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "never become a pass") {
		t.Errorf("the refusal must say why it will not be silent: %s", rec.Body.String())
	}
}

// The correlation names the policies CISA's tool failed and ours did not — the reason to run it.
func TestScubaIngest_NamesWhereOurDetectionWasSilent(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})

	// Pick two real mapped policies from the catalogue the bench proves by execution, so this test
	// cannot pass against a mapping that does not exist.
	var withRule []bench.SCuBAPolicy
	for _, p := range bench.SCuBACatalog() {
		if len(p.Rules) == 1 && !strings.HasPrefix(p.Rules[0], "~") {
			withRule = append(withRule, p)
		}
		if len(withRule) == 2 {
			break
		}
	}
	if len(withRule) < 2 {
		t.Skip("catalogue has fewer than two singly-mapped policies")
	}
	caught, missed := withRule[0], withRule[1]

	// Our engine fired for the first policy only.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", RuleID: caught.Rules[0],
		Severity: types.SeverityHigh, Title: "caught"})

	doc, _ := json.Marshal(map[string]any{"Results": []any{
		map[string]any{"ControlID": caught.ID, "Result": "Fail", "Criticality": "Shall"},
		map[string]any{"ControlID": missed.ID, "Result": "Fail", "Criticality": "Shall"},
	}})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "POST", "/v1/scuba/ingest", "t1", string(doc))
	if rec.Code != 200 {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		AgreedFail int `json:"agreed_fail"`
		WeMissed   int `json:"we_missed"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.AgreedFail != 1 || got.WeMissed != 1 {
		t.Errorf("want 1 corroborated and 1 gap, got agreed=%d weMissed=%d (%s)",
			got.AgreedFail, got.WeMissed, rec.Body.String())
	}
}
