package platformapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The contract: a reason the product is not fully working must reach the screen.
//
// Three defects shipped with the same shape — the backend knew and the screen did not say. They were
// fixed one at a time, which protects against those three and nothing else. These tests hold the
// arrangement that replaces that: every declared reason is really produced, every produced reason
// carries what a person needs to act, and a healthy workspace stays quiet.

func stateDeps(t *testing.T) (Deps, store.Store) {
	t.Helper()
	st := store.NewMemory()
	return Deps{Store: st}, st
}

// THE GUARD. A kind can be declared and never emitted — which is precisely the silent-signal bug, one
// level up: the constant exists, the frontend switches on it, and nothing ever sets it. Each kind is
// driven here by the state that should produce it.
func TestEveryDeclaredKindIsActuallyProduced(t *testing.T) {
	ctx := context.Background()
	produced := map[string]bool{}

	// automation_halted + connection_broken
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A", AgentsHalted: true})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnRevoked})
	for _, g := range d.computeDegradations(ctx, "t") {
		produced[g.Kind] = true
	}

	// ai_off — a workspace with no model and no deliberate choice
	d2, st2 := stateDeps(t)
	_ = st2.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A", Plan: platform.PlanFree})
	for _, g := range d2.computeDegradations(ctx, "t") {
		produced[g.Kind] = true
	}

	// last_scan_failed — a real failed job
	d3, st3 := stateDeps(t)
	_ = st3.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	pool := jobs.NewPool(1, 4, 8, 0, func() string { return "j1" })
	d3.Jobs = pool
	job, err := pool.Enqueue("rescan", "t", func(context.Context) (any, error) {
		return nil, errBoom{}
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, pool, job.ID)
	for _, g := range d3.computeDegradations(ctx, "t") {
		produced[g.Kind] = true
	}

	// cloud_coverage_incomplete — a stored snapshot that recorded what it could not answer
	d4, st4 := stateDeps(t)
	_ = st4.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	snaps := cloudsnap.NewMemStore()
	_ = snaps.Put(ctx, cloudsnap.Snapshot{
		TenantID: "t", Inventory: []byte(`{"account_id":"1"}`),
		CoverageGaps: map[string]string{
			"privilege-escalation": "no policy documents in the snapshot — populate `policies`.",
		},
	})
	d4.CloudSnapshots = snaps
	for _, g := range d4.computeDegradations(ctx, "t") {
		produced[g.Kind] = true
	}

	for _, kind := range AllDegradationKinds() {
		if !produced[kind] {
			t.Errorf("%q is declared but no state produced it — a reason nothing can emit is invisible "+
				"in exactly the way this file exists to prevent", kind)
		}
	}
}

// Every emitted reason must be actionable by a person: what is not happening, what that means for what
// they are reading, and where to go. A bar that says "degraded" teaches people to ignore the bar.
func TestEveryDegradationIsActionable(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A", AgentsHalted: true, Plan: platform.PlanFree})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnDegraded})

	got := d.computeDegradations(ctx, "t")
	if len(got) == 0 {
		t.Fatal("a halted tenant with a broken connection produced no degradations")
	}
	for _, g := range got {
		if strings.TrimSpace(g.Title) == "" {
			t.Errorf("%s has no title", g.Kind)
		}
		if len(strings.TrimSpace(g.Detail)) < 25 {
			t.Errorf("%s detail is too thin to act on: %q", g.Kind, g.Detail)
		}
		if degradationRank[g.Severity] == 0 && g.Severity != "critical" {
			t.Errorf("%s has severity %q, which is not one of critical/warning/info", g.Kind, g.Severity)
		}
	}
}

// THE ONE THAT MATTERS MOST. A failed scan must carry its real cause, because the failure mode being
// prevented is an empty findings list reading as "you have no vulnerabilities".
func TestFailedScan_SaysAnEmptyResultIsNotAllClear(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	pool := jobs.NewPool(1, 4, 8, 0, func() string { return "j1" })
	d.Jobs = pool
	job, _ := pool.Enqueue("rescan", "t", func(context.Context) (any, error) { return nil, errBoom{} })
	waitJob(t, pool, job.ID)

	var found *Degradation
	for i, g := range d.computeDegradations(ctx, "t") {
		if g.Kind == DegradationLastScanFailed {
			found = &d.computeDegradations(ctx, "t")[i]
		}
	}
	if found == nil {
		t.Fatal("a failed scan produced no degradation — the findings list would render empty with no reason")
	}
	if !strings.Contains(found.Detail, "does not mean nothing was found") {
		t.Errorf("the detail does not correct the dangerous reading: %q", found.Detail)
	}
	if !strings.Contains(found.Detail, "boom") {
		t.Errorf("the real cause was dropped, so an operator cannot fix it: %q", found.Detail)
	}
}

// A healthy workspace must be SILENT. A bar that always shows something is the same as no bar.
func TestHealthyWorkspace_ProducesNothing(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{
		ID: "t", Name: "A", Plan: platform.PlanGrowth,
		LLM: &platform.LLMConfig{Provider: "anthropic", Model: "claude-opus-5", KeyRef: "sealed"},
	})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnActive})

	if got := d.computeDegradations(ctx, "t"); len(got) != 0 {
		t.Errorf("a healthy workspace produced %d degradation(s): %+v", len(got), got)
	}
}

// Deterministic-only is a CHOICE, not a fault. Telling someone on every page that the thing they
// turned off is off reframes their decision as a defect.
func TestChosenDeterministic_IsNotReportedAsDegraded(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{
		ID: "t", Name: "A", Plan: platform.PlanFree, AIMode: platform.AIModeDeterministic,
	})
	for _, g := range d.computeDegradations(ctx, "t") {
		if g.Kind == DegradationAIOff {
			t.Error("a customer who chose deterministic-only is told their engineer is broken")
		}
	}
}

// A never-nil list: `null` would crash the shell that renders it on every page (#1129's class).
func TestDegradations_AreNeverNil(t *testing.T) {
	d, _ := stateDeps(t)
	if d.computeDegradations(context.Background(), "missing-tenant") == nil {
		t.Error("nil degradations serialize as null and break the component that renders them")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "docker daemon unreachable: boom" }

func waitJob(t *testing.T, p *jobs.Pool, id string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if j, ok := p.Get(id); ok && (j.Status == "failed" || j.Status == "done") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not settle")
}
