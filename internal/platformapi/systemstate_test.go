package platformapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
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

	// threat_intel_stale — driven from a FIXED clock, not from today's date.
	//
	// This kind fires on the real clock as things stand (the embedded snapshot is 113 days old as
	// this is written), so the guard would pass without driving anything — and would silently stop
	// covering this kind the moment someone refreshes the snapshot. A guard that only works while
	// the bug is present is not a guard.
	d5, st5 := stateDeps(t)
	_ = st5.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A"})
	restore := nowUTC
	nowUTC = func() time.Time { return hooks.ThreatIntelSnapshot.Add(400 * 24 * time.Hour) }
	for _, g := range d5.computeDegradations(ctx, "t") {
		produced[g.Kind] = true
	}
	nowUTC = restore

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

	// Healthy includes CURRENT THREAT INTEL, which is world state rather than anything about this
	// tenant. Pinned to a fresh corpus rather than left on the wall clock: the embedded snapshot is
	// months old, so on the real clock this test would fail for a reason that has nothing to do with
	// the workspace being healthy — and pinning states the premise instead of hiding it.
	restore := nowUTC
	nowUTC = func() time.Time { return hooks.ThreatIntelSnapshot.Add(24 * time.Hour) }
	defer func() { nowUTC = restore }()

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

// ADR 0022 §2 — a message must not tell a reader to do something they cannot do.
//
// The threat-intel banner told every tenant to "set TSENGINE_THREAT_INTEL_CORPUS and run
// `tsengine corpus refresh`". The corpus is global world-state (CLAUDE.md §7): it lives with the
// binary, and a tenant on a hosted deployment has neither. They were handed homework they could not
// do, in an alarm-coloured band, on the first screen after login.
//
// This asserts the property rather than the instance: nothing a TENANT can see may contain an
// environment variable, a shell command, or a host-level instruction.
func TestTenantVisibleDegradationsCarryNoOperatorInstructions(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A", AgentsHalted: true, Plan: platform.PlanFree})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnDegraded})

	// Operator-shaped things: an env var we own, our CLI, or a host the customer does not run.
	operatorOnly := []string{"TSENGINE_", "tsengine corpus", "the binary", "refresh job", "cisa.gov", "first.org"}

	for _, g := range VisibleTo(d.computeDegradations(ctx, "t"), false) {
		body := g.Title + " " + g.Detail
		for _, frag := range operatorOnly {
			if strings.Contains(body, frag) {
				t.Errorf("tenant-visible degradation %q contains the operator-only instruction %q.\n"+
					"A tenant cannot set an env var or run our CLI — the corpus is global world-state "+
					"(CLAUDE.md §7). Give them the CONSEQUENCE and route the remedy to AudienceOperator.\n"+
					"  detail: %s", g.Kind, frag, g.Detail)
			}
		}
	}
}

// Every declared kind must have an audience, so a new one cannot quietly reach nobody.
func TestEveryDegradationKindHasAnAudience(t *testing.T) {
	for _, kind := range AllDegradationKinds() {
		a, ok := degradationAudience[kind]
		if !ok {
			t.Errorf("%q has no entry in degradationAudience — defaulting is safe at runtime, but an "+
				"unassigned kind means nobody decided who it is for", kind)
			continue
		}
		switch a {
		case AudienceBoth, AudienceTenant, AudienceOperator:
		default:
			t.Errorf("%q has audience %q, which is not one of both/tenant/operator", kind, a)
		}
	}
}

// The operator half must survive the filter — the remedy has to reach the one person who can act.
func TestOperatorSeesTheRemedyTenantsDoNot(t *testing.T) {
	ctx := context.Background()
	d, st := stateDeps(t)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "A", Plan: platform.PlanFree})

	all := d.computeDegradations(ctx, "t")
	var opHasRemedy bool
	for _, g := range VisibleTo(all, true) {
		if g.Kind == DegradationThreatIntelStale && strings.Contains(g.Detail, "TSENGINE_") {
			opHasRemedy = true
		}
	}
	if !opHasRemedy {
		t.Error("the operator sees no remedy for a stale corpus — the audience split removed the " +
			"instruction from everyone instead of routing it")
	}
}
