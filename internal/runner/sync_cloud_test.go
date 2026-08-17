package runner

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// syncCloud makes the connected cloud account a continuously-monitored surface. Everything it drives
// already existed — the live read, the drift diff, the incident opener — but only a human pressing
// Sync ever ran it, so a bucket that turned public at 2am waited to be noticed.

func driftFinding() types.Finding {
	return types.Finding{
		ID: "d1", RuleID: "clouddrift::resource-became-public", Endpoint: "arn:aws:s3:::customer-exports",
		Severity: types.SeverityCritical, Title: "Bucket customer-exports became public",
	}
}

// ── THE PROPERTY THE WIRING EXISTS FOR ───────────────────────────────────────────────────────────

// A drift finding must SURVIVE the pass that discovered it.
//
// This is the failure the design had to avoid rather than a hypothetical. The syncer stores its
// findings and opens incidents for them itself; the same pass then reconciles, and the reconciler
// RESOLVES any open incident whose finding is absent from the pass's view of present state. So a
// syncer that stored drift without handing it back would open an incident and close it seconds
// later — continuous monitoring that reports nothing, which is indistinguishable from a quiet estate.
func TestSyncCloud_DriftIncidentSurvivesTheSamePass(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	// A scannable asset, because the reconciler only runs when a real scan established present state.
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: false}, // clean scan: the ONLY finding is the cloud drift
		NewID:   func() string { n++; return itoa(n) },
		CloudSyncer: func(ctx context.Context, tenantID string) ([]types.Finding, error) {
			f := driftFinding()
			_ = st.PutFinding(ctx, tenantID, f) // the real syncer persists before returning
			return []types.Finding{f}, nil
		},
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}

	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if got := openCount(t, st); got != 1 {
		t.Fatalf("a bucket that became public left %d open incidents, want 1 — the drift was "+
			"detected and then resolved by the same pass, so nobody is ever told", got)
	}
}

// And it resolves when the drift stops appearing — the guard above must not be satisfiable by an
// incident that can never close.
func TestSyncCloud_DriftIncidentResolvesWhenTheChangeIsReverted(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})

	drifting := true
	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: false},
		NewID:   func() string { n++; return itoa(n) },
		CloudSyncer: func(ctx context.Context, tenantID string) ([]types.Finding, error) {
			if !drifting {
				return nil, nil // the bucket was made private again
			}
			f := driftFinding()
			_ = st.PutFinding(ctx, tenantID, f)
			return []types.Finding{f}, nil
		},
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}

	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if openCount(t, st) != 1 {
		t.Fatalf("setup: expected the drift incident to open")
	}
	drifting = false
	// Two passes: resolution requires the absence to persist, so a single quiet scan cannot report
	// a live drift as reverted.
	for i := 0; i < 2; i++ {
		if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := openCount(t, st); got != 0 {
		t.Errorf("the change was reverted but %d incident(s) stayed open", got)
	}
}

// ── BEST-EFFORT: A CLOUD PROBLEM MUST NOT COST THE WHOLE PASS ────────────────────────────────────

// A failed cloud read must not abort the pass. An expired role or a throttled API is not a reason to
// abandon scan output, SaaS posture and OSINT that were gathered successfully.
func TestSyncCloud_ReadFailureDoesNotAbortThePass(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: &togglingScanner{Open: true}, // this finding must still reach an incident
		NewID:   func() string { n++; return itoa(n) },
		CloudSyncer: func(context.Context, string) ([]types.Finding, error) {
			return nil, errors.New("AssumeRole: access denied")
		},
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}

	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatalf("a failed cloud read aborted the whole monitoring pass: %v", err)
	}
	if got := openCount(t, st); got != 1 {
		t.Errorf("the scanned finding produced %d incidents, want 1 — a cloud failure cost the "+
			"rest of the pass", got)
	}
}

// A read that was never POSSIBLE is not a failure. Most tenants have no cloud account connected, and
// treating that as an error would log noise every pass forever — burying the failures that matter.
func TestSyncCloud_UnavailableIsSilentAndHarmless(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})

	svc := &Service{Store: st, NewID: itoa1,
		CloudSyncer: func(context.Context, string) ([]types.Finding, error) {
			return nil, fmt.Errorf("%w: no AWS account is connected", ErrCloudSyncUnavailable)
		}}
	if out := svc.syncCloud(ctx, "t1"); out != nil {
		t.Errorf("an unavailable cloud read produced findings: %+v", out)
	}
}

// No syncer wired → no-op. The capability is additive: a deployment without live cloud read behaves
// exactly as it did before.
func TestSyncCloud_NoSyncerIsNoop(t *testing.T) {
	svc := &Service{Store: store.NewMemory(), NewID: itoa1}
	if out := svc.syncCloud(context.Background(), "t1"); out != nil {
		t.Errorf("no CloudSyncer should be a no-op, got %+v", out)
	}
}

// An unchanged account yields nothing, and that silence means "nothing changed" — never "we did not
// look". Grounded (§10): findings come only from a real diff.
func TestSyncCloud_UnchangedAccountYieldsNothing(t *testing.T) {
	svc := &Service{Store: store.NewMemory(), NewID: itoa1,
		CloudSyncer: func(context.Context, string) ([]types.Finding, error) { return nil, nil }}
	if out := svc.syncCloud(context.Background(), "t1"); len(out) != 0 {
		t.Errorf("an unchanged account invented %d findings", len(out))
	}
}
