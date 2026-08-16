package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE AUTONOMY CLAIM, EXECUTED.
//
// internal/bench/autonomy.go says most of the engineer's job runs unattended and cites the code that
// makes it so. A citation is not a demonstration: every one of those entries is a sentence I wrote
// about code I read, and this session already produced two gradings that were wrong in opposite
// directions. So this runs an actual monitoring pass with NO human call anywhere in it and asserts
// what the tenant is left holding.
//
// The shape it proves is the whole product thesis in one test: the agent finds it, decides it matters,
// prepares the change — and then STOPS, holding it for a person. Autonomy up to the point of
// consequence, and not one step past it.

// countingApplier is the outside world. Any call here is a side effect that reached a customer system
// without a human, which is the one thing the loop must never do on its own for a gated action.
type countingApplier struct{ applied int }

func (c *countingApplier) Apply(context.Context, platform.Action) error { c.applied++; return nil }

// repoScanner emits a finding on a REPOSITORY asset, the class remediate.Propose can act on (it opens
// a PR — tier 2, gated). A workspace finding would file a tier-1 ticket and auto-apply, which would
// prove the opposite of what is being asserted.
type repoScanner struct{}

func (repoScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	return []types.Finding{{
		ID: "f-sqli", RuleID: "semgrep::sql-injection", Tool: "semgrep",
		Endpoint: "acme/app/search.py:41", Severity: types.SeverityCritical,
		Title: "SQL injection in order search", CWE: []string{"CWE-89"},
	}}, nil
}

func TestAutonomy_OnePassFindsDecidesAndPreparesWithoutAHuman(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAsset(ctx, platform.Asset{
		ID: "a1", TenantID: "t1", Type: "repository", Target: "acme/app",
		Meta: map[string]string{"full_name": "acme/app"},
	}); err != nil {
		t.Fatal(err)
	}

	app := &countingApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}
	n := 0
	id := func() string { n++; return "id" + itoa(n) }

	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: repoScanner{}, NewID: id,
		Detector: &detect.Detector{Store: st, NewID: id},
		Desk:     desk,
		// A stand-in for remediate.Propose, which cannot be imported here — remediate imports runner, so
		// using the real one is an import cycle. That is acceptable because this test is about the LOOP's
		// WIRING (does an unattended pass reach the proposer at all, and does the result stop at the
		// desk), not about remediate's finding→action mapping, which has its own tests. It returns the
		// same shape the real one does for a repository finding: a tier-2 open-PR action, gated.
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			return platform.Action{
				ID: id(), TenantID: a.TenantID, FindingID: f.ID, Kind: platform.ActOpenPR,
				Tier: platform.GateTier, Status: platform.ActProposed,
				Title: "fix " + f.Title,
			}, true
		},
	}

	// ONE PASS. No approval, no click, no request — the scheduler's tick and nothing else.
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatalf("an unattended pass errored: %v", err)
	}

	// 1. IT FOUND SOMETHING. Detection ran without being asked.
	findings, err := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("AUTONOMY BROKEN: a pass with no human involvement stored no findings — the engineer " +
			"only works when asked")
	}

	// 2. IT DECIDED AND PREPARED. A change exists that nobody requested.
	acts, err := st.ListActions(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) == 0 {
		t.Fatal("AUTONOMY BROKEN: findings were stored but no remediation was proposed. Detection " +
			"without proposal is a scanner, not an engineer — the human still has to work out what to do")
	}
	if acts[0].FindingID == "" {
		t.Errorf("the queued change cites no finding — a human is asked to approve something with no " +
			"stated cause")
	}

	// 3. AND THEN IT STOPPED. The gated change is waiting, not applied.
	if app.applied != 0 {
		t.Errorf("HUMAN BYPASSED: %d change(s) reached a customer system in an unattended pass. Autonomy "+
			"must end at the point of consequence", app.applied)
	}
	if acts[0].Status == platform.ActApplied {
		t.Errorf("action %s is applied; expected it queued for approval", acts[0].ID)
	}
}

// The other half of the claim: the loop must not need a human to NOTICE a fix worked either. A second
// pass over a now-clean estate has to resolve what it opened, unattended.
func TestAutonomy_TheLoopClosesItselfWhenTheIssueGoesAway(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})

	sc := &togglingScanner{Open: true}
	n := 0
	id := func() string { n++; return itoa(n) }
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: sc, NewID: id,
		Detector: &detect.Detector{Store: st, NewID: id},
	}

	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if openCount(t, st) == 0 {
		t.Fatal("no incident opened on the first pass — nothing to close")
	}

	sc.Open = false // somebody fixed it out in the world; nobody told us
	// Two passes: resolution now requires the absence to PERSIST, because a scanner that has one
	// quiet run must not be read as "remediated" (dalfox found 7 vulnerable cases in one run and 9
	// in the next on an unchanged target). The loop still closes itself with no human — one cycle
	// later — which is what this test is actually protecting.
	for i := 0; i < 2; i++ {
		if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := openCount(t, st); got != 0 {
		t.Errorf("AUTONOMY BROKEN: %d incident(s) still open after the issue disappeared — a human has "+
			"to close them by hand, which is the queue-rot every security product dies of", got)
	}
}
