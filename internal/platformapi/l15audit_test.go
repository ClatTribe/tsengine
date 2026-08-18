package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A finding the FP filter DISMISSED exists nowhere else in the product — it is not in the findings
// list, not in issues, not in incidents. If the audit surface does not carry it, the security
// engineer has no way to discover that the AI decided not to show them something, which is the one
// thing practitioners say they must be able to check before trusting the output.
func TestL15Audit_SurfacesWhatTheChainSuppressed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutEngagement(ctx, platform.Engagement{
		ID: "e1", TenantID: "t1", AssetID: "a1",
		L15Audit: []types.AuditEntry{
			{FindingID: "f-1", Action: "dismiss", Rule: "fp_filter::nuclei::generic-tech-fingerprint", Reason: "planted decoy shape"},
			{FindingID: "f-2", Action: "demote", FromSeverity: types.SeverityHigh, ToSeverity: types.SeverityInfo, Rule: "fp_filter::nuclei::generic-tech-fingerprint"},
			{FindingID: "f-3", Action: "demote", FromSeverity: types.SeverityMedium, ToSeverity: types.SeverityLow, Rule: "fp_filter::other"},
		},
	})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/l15-audit", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got l15AuditView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Total != 3 {
		t.Errorf("total = %d, want 3", got.Total)
	}
	if got.Dropped != 1 {
		t.Errorf("dropped = %d, want 1 — a dismissed finding is invisible everywhere else", got.Dropped)
	}
	if got.Demoted != 2 {
		t.Errorf("demoted = %d, want 2", got.Demoted)
	}
	// The noisiest rule must lead: a single filter rule suppressing many findings is the decision an
	// engineer is most likely to want to argue with.
	if len(got.ByRule) == 0 || got.ByRule[0].Rule != "fp_filter::nuclei::generic-tech-fingerprint" {
		t.Errorf("by_rule should lead with the noisiest rule, got %+v", got.ByRule)
	}
	if got.Note != "" {
		t.Errorf("with real entries there should be no caveat note, got %q", got.Note)
	}
}

// An empty result must not read as "nothing was suppressed". Scans that predate the trail, or ran
// with L1.5 disabled, record nothing — and "we did not look" is a different claim from "there was
// nothing" (§10, the same discipline as coverage and posture).
func TestL15Audit_EmptyIsGroundedNotReassuring(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	// A scan happened, but it recorded no trail.
	_ = st.PutEngagement(ctx, platform.Engagement{ID: "e1", TenantID: "t1", AssetID: "a1"})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/l15-audit", "t1", "")
	var got l15AuditView
	_ = json.Unmarshal(rec.Body.Bytes(), &got)

	if got.ScansTotal != 1 || got.ScansWithAudit != 0 {
		t.Fatalf("precondition: want 1 scan with no trail, got total=%d audited=%d", got.ScansTotal, got.ScansWithAudit)
	}
	if got.Note == "" {
		t.Fatal("an empty trail over a scanned estate must be explained, or it reads as 'nothing was suppressed'")
	}
	if !strings.Contains(got.Note, "not evidence") {
		t.Errorf("the note must say absence is not evidence, got %q", got.Note)
	}
}
