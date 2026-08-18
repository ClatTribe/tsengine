package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Cross-surface detection is going to run on every pass that changes a surface, so running it twice
// over an UNCHANGED estate must not produce the same finding twice. One cross-surface fact is one
// finding; a new row per pass would bury the customer in copies of a problem they already have, and
// would make "how many issues do I have" a function of how often we looked.
func TestEstateDetect_IsIdempotentOverAnUnchangedEstate(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	// The identity join: one person, two surfaces.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f-osint", RuleID: "osint::stealer-log",
		Endpoint: "alice@acme.com", Severity: types.SeverityCritical, Title: "Stealer-log exposure"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f-idp", RuleID: "operate::admin-without-mfa",
		Endpoint: "alice@acme.com", Severity: types.SeverityHigh, Title: "Admin without MFA"})

	if rec := do(h, "POST", "/v1/estate/detect", "t1", ""); rec.Code != 200 {
		t.Fatalf("first detect: %d %s", rec.Code, rec.Body.String())
	}
	first := countEstateFindings(t, st)
	if first == 0 {
		t.Fatalf("the identity join produced no finding, so this test proves nothing")
	}

	if rec := do(h, "POST", "/v1/estate/detect", "t1", ""); rec.Code != 200 {
		t.Fatalf("second detect: %d %s", rec.Code, rec.Body.String())
	}
	if second := countEstateFindings(t, st); second != first {
		t.Errorf("re-running detection over an unchanged estate went from %d finding(s) to %d — "+
			"each pass files a fresh copy of the same fact", first, second)
	}
}

func countEstateFindings(t *testing.T, st store.Store) int {
	t.Helper()
	all, _ := st.ListFindings(t.Context(), "t1", store.FindingFilter{})
	n := 0
	for _, f := range all {
		if strings.HasPrefix(f.RuleID, "estate::") {
			n++
		}
	}
	return n
}

// THE HOOK THAT MAKES THE JOIN REACHABLE. The identity join needs an OSINT finding and an identity
// finding, and neither arrives through a door that detects inline — so before this hook existed the
// join only fired for tenants who happened to post a cloud inventory afterwards. This drives the
// monitoring-pass hook directly and asserts the finding appears.
func TestDetectEstateEachPass_FindsAJoinNoIngestDoorWouldHave(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	ctx := t.Context()

	// Exactly the two findings the identity join needs, stored as their own ingests would store them.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f-osint", RuleID: "osint::stealer-log",
		Endpoint: "alice@acme.com", Severity: types.SeverityCritical, Title: "Stealer-log exposure"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f-idp", RuleID: "operate::admin-without-mfa",
		Endpoint: "alice@acme.com", Severity: types.SeverityHigh, Title: "Admin without MFA"})

	d.DetectEstateEachPass(ctx, "t1")

	if n := countEstateFindings(t, st); n == 0 {
		t.Fatalf("the monitoring pass found no cross-surface finding for an admin whose password is in " +
			"a stealer log — the join is unreachable in normal operation")
	}

	// And running again must not duplicate: this fires on EVERY pass.
	before := countEstateFindings(t, st)
	d.DetectEstateEachPass(ctx, "t1")
	if after := countEstateFindings(t, st); after != before {
		t.Errorf("a second pass took the count from %d to %d", before, after)
	}
}

// A tenant with nothing connected must produce nothing — the pass runs for every tenant, so the
// quiet case is the common one and it must not invent a finding or fail.
func TestDetectEstateEachPass_EmptyTenantIsQuiet(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	d.DetectEstateEachPass(t.Context(), "t1")
	if n := countEstateFindings(t, st); n != 0 {
		t.Errorf("an empty tenant produced %d cross-surface finding(s)", n)
	}
}
