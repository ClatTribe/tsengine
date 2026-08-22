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

// cleanScanner reports nothing, which is what a genuinely clean asset looks like.
type cleanScanner struct{}

func (cleanScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	return nil, nil
}

// "Fixed" is the strongest positive claim this product makes, and FixStatusFixed is TERMINAL — once
// recorded it is never re-evaluated. It is decided entirely by ABSENCE: retest.Verify marks a
// remediation fixed when its finding keys are missing from the pass.
//
// THE GAP IS THE PARTIAL PASS, not the failed one. A pass that fails outright is already safe: the
// reconcile + retest block is gated on firstErr == nil && scanned > 0, so a tenant whose only asset
// errors concludes nothing. But an asset skipped for an INACTIVE CONNECTION sets neither of those. On
// a tenant where other assets scan fine the pass looks complete — firstErr nil, scanned > 0 — and
// retest runs over findings that are missing the skipped asset entirely.
//
// One revoked GitHub token among several connections is enough, and OM-5 fail-closed makes that
// skip deliberate rather than exceptional.
func TestRescanTenant_APartialPassDoesNotConfirmFixesOnTheSkippedAsset(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})

	// The asset the remediation was applied to, behind a REVOKED connection → skipped.
	_ = st.PutConnection(ctx, platform.Connection{
		ID: "c-dead", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnRevoked,
	})
	_ = st.PutAsset(ctx, platform.Asset{
		ID: "a-skipped", TenantID: "t1", Type: "workspace", Target: "acme", ConnectionID: "c-dead",
	})
	// A second asset with no connection, which scans fine — so the pass looks complete.
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", Type: "workspace", Target: "other"})

	_ = st.PutAction(ctx, platform.Action{
		ID: "act-1", TenantID: "t1", Status: platform.ActApplied,
		FindingKeys: []string{"operate::stale-account|acme"},
	})

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: cleanScanner{}, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatalf("the pass should succeed — that is the point: it LOOKS complete: %v", err)
	}

	if v := actionVerification(t, st); v != nil && v.Status == platform.FixStatusFixed {
		t.Fatal("the asset this remediation targets was never scanned (revoked connection), so its " +
			"silence is not evidence the fix landed — yet it was terminally marked fixed. The pass " +
			"succeeded and scanned another asset, so the firstErr/scanned guards did not catch it.")
	}
}

// The control, and the thing this must not break: when every asset really was scanned and the finding
// really is gone, the fix IS confirmed. Suppressing that would trade a false confirmation for never
// confirming anything, which is the same failure pointed the other way.
func TestRescanTenant_AFullyScannedPassStillConfirmsARealFix(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	appliedFix(t, st, "operate::stale-account|acme")

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: cleanScanner{}, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatalf("clean pass: %v", err)
	}
	v := actionVerification(t, st)
	if v == nil || v.Status != platform.FixStatusFixed {
		t.Fatalf("every asset scanned and the finding is gone — that is a real confirmed fix, got %+v", v)
	}
}
