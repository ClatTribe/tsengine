package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// PROOF CONTINUITY (ADR 0024 C16 / Sprint 0 R2).
//
// A monitoring pass re-derives four things: asset scans, SaaS posture, OSINT, cloud drift. The cloud
// engineer, the code engineer, codesweep, the CI-identity assessors, TPRM, device posture, the
// warehouse ingest and the identity event stream are ONE-SHOT — nothing re-runs them. Their findings
// are therefore missing from every pass by construction, and the two consumers that reason from
// absence were reading that as evidence.
//
// These two tests are the probes that found it, kept as regression tests. Both failed before the fix.

func continuityService(t *testing.T, st store.Store, det *detect.Detector) *Service {
	t.Helper()
	n := 100
	return &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: cleanScanner{}, NewID: func() string { n++; return itoa(n) }, Detector: det,
	}
}

// The cloud engineer's own attack-path incident must not resolve itself. Nothing re-ran the agent,
// the path was never re-checked, and nobody fixed anything.
func TestRescanTenant_AnAgentIncidentDoesNotResolveItself(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	// One ordinary scannable asset, so the pass IS authoritative — firstErr nil, scanned > 0, not
	// degraded. That is the point: this is a complete pass, it simply never asked the agent.
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", Type: "workspace", Target: "acme"})

	n := 0
	det := &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }}
	path := types.Finding{
		ID: "cf1", RuleID: "cloudagent::attack-path::abc", Tool: "cloudagent",
		Severity: types.SeverityCritical, Endpoint: "arn:aws:s3:::customer-exports",
		Title: "customer-exports — reachable attack path",
	}
	_ = st.PutFinding(ctx, "t1", path)
	if _, err := det.OpenFor(ctx, "t1", []types.Finding{path}, nil); err != nil {
		t.Fatal(err)
	}

	svc := continuityService(t, st, det)
	for i := 0; i < 3; i++ {
		if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	incs, _ := st.ListIncidents(ctx, "t1")
	if len(incs) != 1 {
		t.Fatalf("want 1 incident, got %d", len(incs))
	}
	if incs[0].Status == platform.IncidentResolved {
		t.Fatal("the cloud engineer's attack-path incident RESOLVED itself over routine passes that " +
			"never ran the agent — absence of a producer nobody re-ran is not evidence of a fix")
	}
	// Not merely unresolved — the absence streak must not be accruing either, or this is the same
	// bug on a longer fuse.
	if incs[0].AbsentPasses != 0 {
		t.Errorf("absent streak = %d after 3 uncovered passes; it should never have started counting",
			incs[0].AbsentPasses)
	}
}

// The same root cause, stronger claim: FixStatusFixed is TERMINAL, so a false confirmation here can
// never be corrected by a later pass.
func TestRescanTenant_AnAgentFixIsNotConfirmedByAPassThatNeverRanTheAgent(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", Type: "workspace", Target: "acme"})
	_ = st.PutAction(ctx, platform.Action{
		ID: "act-1", TenantID: "t1", Status: platform.ActApplied,
		FindingKeys: []string{"cloudagent::attack-path::abc|arn:aws:s3:::customer-exports"},
	})

	n := 0
	svc := continuityService(t, st, &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }})
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if v := actionVerification(t, st); v != nil && v.Status == platform.FixStatusFixed {
		t.Fatalf("a cloud attack-path fix was TERMINALLY confirmed (%q) by a pass that never ran the "+
			"cloud engineer", v.Evidence)
	}
}

// THE MIRROR, and the failure this must not trade for. A producer the pass really DID run stays
// fully resolvable: silence from something that ran is evidence. Without this the change would swap
// a false "fixed" for a permanent false "still broken", which is the same defect reversed.
func TestRescanTenant_ACoveredProducerStillResolves(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", Type: "workspace", Target: "acme"})

	n := 0
	det := &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }}
	// operate is the workspace scanner's producer — covered by a successful workspace scan even
	// though it dispatches no tools.
	stale := types.Finding{
		ID: "of1", RuleID: "operate::stale-account", Tool: "operate",
		Severity: types.SeverityHigh, Endpoint: "acme", Title: "stale admin account",
	}
	if _, err := det.OpenFor(ctx, "t1", []types.Finding{stale}, nil); err != nil {
		t.Fatal(err)
	}

	svc := continuityService(t, st, det)
	for i := 0; i < 3; i++ {
		if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	incs, _ := st.ListIncidents(ctx, "t1")
	if len(incs) != 1 || incs[0].Status != platform.IncidentResolved {
		t.Fatalf("a workspace scan really does re-derive operate findings, so a fixed one must still "+
			"resolve; got status=%q absent=%d", incs[0].Status, incs[0].AbsentPasses)
	}
}
