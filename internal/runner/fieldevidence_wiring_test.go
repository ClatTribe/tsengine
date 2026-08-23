package runner

import (
	"context"
	"strconv"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// history stores N already-verified remediations for one class, each a LABELLED example: the re-scan
// said gone, and a live re-attack then either agreed or contradicted it.
func history(t *testing.T, st store.Store, class string, n int, contradicted bool) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		v := &platform.FixVerification{Status: platform.FixStatusFixed, RescanSaidFixed: true}
		if contradicted {
			v.Disagreement = platform.DisagreeRescanMissedLiveExploit
		}
		_ = st.PutAction(ctx, platform.Action{
			ID: "hist-" + strconv.Itoa(i), TenantID: "t1", Status: platform.ActApplied,
			FindingKeys: []string{class + "|old-" + strconv.Itoa(i)}, Verification: v,
		})
	}
}

func newAppliedFix(t *testing.T, st store.Store, key string) {
	t.Helper()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})
	_ = st.PutAction(ctx, platform.Action{
		ID: "act-new", TenantID: "t1", Status: platform.ActApplied, FindingKeys: []string{key},
	})
}

func verificationOf(t *testing.T, st store.Store, id string) *platform.FixVerification {
	t.Helper()
	acts, err := st.ListActions(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.ID == id {
			return a.Verification
		}
	}
	t.Fatalf("action %s not found", id)
	return nil
}

func svcFor(st store.Store) *Service {
	n := 0
	return &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner:  &togglingScanner{Open: false}, // the finding is gone → the re-scan says "fixed"
		NewID:    func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}
}

// THE WIRING TEST (ADR 0025 F1). The components being correct in isolation is not the same as the
// monitoring pass actually consulting them — this repo has shipped that exact gap before, with
// direct-call tests passing while the routing was absent. This drives the whole arc through
// RescanTenant.
//
// A tenant whose own history shows clean re-scans for this class HAVE been contradicted by a live
// exploit must not get a terminal "fixed" from a re-scan alone.
func TestRescanTenant_ContradictedHistoryWithholdsTheRescanConfirmation(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	newAppliedFix(t, st, "operate::stale-account|acme")
	history(t, st, "operate::stale-account", 6, true)

	if _, err := svcFor(st).RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	v := verificationOf(t, st, "act-new")
	if v == nil {
		t.Fatal("the applied fix got no verification at all")
	}
	if v.Status != platform.FixStatusRescanUnconfirmed {
		t.Fatalf("status = %q, want %q — the pass is not consulting the field-evidence corpus",
			v.Status, platform.FixStatusRescanUnconfirmed)
	}
}

// The mirror, which matters just as much: a tenant with a CLEAN history, or with no history at all,
// must see exactly today's behaviour. A corpus that only ever tightens is still wrong if it tightens
// on everyone — and this is what proves an empty corpus changes nothing.
func TestRescanTenant_CleanOrAbsentHistoryStillConfirmsOnRescan(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*testing.T, store.Store)
	}{
		{"no history at all", func(*testing.T, store.Store) {}},
		{"clean history", func(t *testing.T, st store.Store) {
			history(t, st, "operate::stale-account", 6, false)
		}},
		{"contradicted history for a DIFFERENT class", func(t *testing.T, st store.Store) {
			history(t, st, "operate::something-else", 6, true)
		}},
		{"too few examples to mean anything", func(t *testing.T, st store.Store) {
			history(t, st, "operate::stale-account", 2, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := store.NewMemory()
			newAppliedFix(t, st, "operate::stale-account|acme")
			tc.seed(t, st)
			if _, err := svcFor(st).RescanTenant(ctx, "t1"); err != nil {
				t.Fatal(err)
			}
			v := verificationOf(t, st, "act-new")
			if v == nil || v.Status != platform.FixStatusFixed {
				got := "none"
				if v != nil {
					got = v.Status
				}
				t.Fatalf("status = %q, want %q — the corpus must only ever DEMAND MORE evidence",
					got, platform.FixStatusFixed)
			}
		})
	}
}
