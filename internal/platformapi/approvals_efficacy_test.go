package platformapi

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func histAct(id, class, rtype, status string) platform.Action {
	return platform.Action{ID: id, TenantID: "t1", Status: platform.ActApplied,
		FindingKeys:  []string{class + "|https://x/" + id},
		Payload:      map[string]any{"remediation_type": rtype},
		Verification: &platform.FixVerification{Status: status}}
}

func pendingAct(class, rtype string) platform.Action {
	return platform.Action{ID: "pending-1", TenantID: "t1", Status: platform.ActPendingApproval,
		Kind: platform.ActFileTicket, FindingKeys: []string{class + "|https://x/new"},
		Payload: map[string]any{"remediation_type": rtype}}
}

func approvals(t *testing.T, st store.Store) []map[string]any {
	t.Helper()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/approvals", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("GET /v1/approvals: %d %s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	return got
}

// THE property (ADR 0025 F2): the human about to approve a fix is told whether THIS kind of fix has
// actually closed THIS kind of finding before. "Closed 8 of 10" and "reopened 5 of 8" are different
// decisions, and before this they read identically.
func TestApprovals_CarryTheRemediationsMeasuredTrackRecord(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	for i := 0; i < 8; i++ {
		_ = st.PutAction(ctx, histAct("h"+strconv.Itoa(i), "nuclei::sqli", "parameterize_query", platform.FixStatusFixed))
	}
	for i := 0; i < 2; i++ {
		_ = st.PutAction(ctx, histAct("n"+strconv.Itoa(i), "nuclei::sqli", "parameterize_query", platform.FixStatusStillPresent))
	}
	_ = st.PutAction(ctx, pendingAct("nuclei::sqli", "parameterize_query"))

	got := approvals(t, st)
	if len(got) != 1 {
		t.Fatalf("want one pending approval, got %d", len(got))
	}
	eff, ok := got[0]["fix_efficacy"].(map[string]any)
	if !ok {
		t.Fatalf("the pending fix carries no track record: %v", got[0])
	}
	num := func(k string) int { f, _ := eff[k].(float64); return int(f) }
	if num("closed") != 8 || num("not_closed") != 2 {
		t.Errorf("want 8 closed / 2 not, got %v", eff)
	}

	// Read-time only: the STORED action must be untouched (mirrors annotateApplyBlocked / annotateSLA).
	stored, _ := st.ListActions(ctx, "t1")
	for _, a := range stored {
		if a.ID == "pending-1" && a.FixEfficacy != nil {
			t.Error("the annotation must not be persisted onto the stored action")
		}
	}
}

// Silence means "not enough history", never "this will work". An action with no track record must be
// left UNANNOTATED — a zeroed record beside a proposed fix reads as a fix that never works.
func TestApprovals_NoTrackRecordIsLeftUnannotated(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAction(ctx, pendingAct("nuclei::sqli", "parameterize_query"))

	got := approvals(t, st)
	if len(got) != 1 {
		t.Fatalf("want one pending approval, got %d", len(got))
	}
	if _, present := got[0]["fix_efficacy"]; present {
		t.Errorf("no history must render nothing at all, got %v", got[0]["fix_efficacy"])
	}
}

// A withheld confirmation (F1) must not be laundered into a success by F2.
func TestApprovals_WithheldConfirmationsAreReportedNotCountedAsClosed(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	for i := 0; i < 5; i++ {
		_ = st.PutAction(ctx, histAct("c"+strconv.Itoa(i), "r1", "t", platform.FixStatusFixed))
		_ = st.PutAction(ctx, histAct("u"+strconv.Itoa(i), "r1", "t", platform.FixStatusRescanUnconfirmed))
	}
	_ = st.PutAction(ctx, pendingAct("r1", "t"))

	eff, ok := approvals(t, st)[0]["fix_efficacy"].(map[string]any)
	if !ok {
		t.Fatal("expected a track record")
	}
	num := func(k string) int { f, _ := eff[k].(float64); return int(f) }
	if num("closed") != 5 || num("unproven") != 5 {
		t.Errorf("want 5 closed / 5 unproven reported separately, got %v", eff)
	}
	if num("not_closed") != 0 {
		t.Errorf("unproven is not a failure either, got not_closed=%d", num("not_closed"))
	}
}

// F1 tightening shrinks F2's denominator, so a class can fall under the floor and go silent for
// exactly the fixes that most need scrutiny. Silence reads as "no history", which is the comfortable
// answer. Mutation showed this path was entirely untested at the API layer.
func TestApprovals_UnscoreableTrackRecordIsReportedAsMutedNotAbsent(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	for i := 0; i < 2; i++ {
		_ = st.PutAction(ctx, histAct("d"+strconv.Itoa(i), "r1", "t", platform.FixStatusFixed))
	}
	for i := 0; i < 9; i++ {
		_ = st.PutAction(ctx, histAct("u"+strconv.Itoa(i), "r1", "t", platform.FixStatusRescanUnconfirmed))
	}
	_ = st.PutAction(ctx, pendingAct("r1", "t"))

	eff, ok := approvals(t, st)[0]["fix_efficacy"].(map[string]any)
	if !ok {
		t.Fatal("a record that exists but cannot be scored must still be reported, not omitted")
	}
	if eff["muted"] != true {
		t.Errorf("it must say it cannot be scored, got %v", eff)
	}
	if f, _ := eff["unproven"].(float64); int(f) != 9 {
		t.Errorf("and say WHY it cannot be scored, got %v", eff)
	}
}
