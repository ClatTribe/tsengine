package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// failingFindingStore stores everything except findings, which is what a full disk or a degraded
// database looks like from here.
type failingFindingStore struct {
	store.Store
	attempts int
}

func (f *failingFindingStore) PutFinding(context.Context, string, types.Finding) error {
	f.attempts++
	return errors.New("disk full")
}

// A finding that failed to persist must not reach `current`.
//
// The caller appends these to the tenant's current finding set, which drives incident
// reconciliation. Returning a finding that was never stored opens an incident with nothing behind
// it: /incidents shows it, /issues does not, and the two views of the same estate disagree with no
// explanation anywhere.
//
// PutFinding is CHECKED at the scan door (it aborts) and at the OSINT ingest door (it skips and
// returns only what it saved). These two autonomous sync paths discarded it — and they are the ones
// that run every monitoring pass with nobody watching.
func TestSyncOSINT_DoesNotReturnAFindingItFailedToStore(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	_ = mem.PutTenant(ctx, platform.Tenant{ID: "t1"})
	// A domain asset, so the collector has something to run over.
	_ = mem.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "domain", Target: "acme.example"})

	st := &failingFindingStore{Store: mem}
	n := 0
	svc := &Service{
		Store: st,
		NewID: func() string { n++; return "f" + itoa(n) },
		// A crt.sh response naming a host outside the monitored inventory — the shape that produces
		// an exposed-host finding.
		OSINTFetcher: func(context.Context, string) ([]byte, error) {
			return []byte(`[{"name_value":"forgotten-staging.acme.example"}]`), nil
		},
	}

	got, _ := svc.syncOSINT(ctx, "t1")
	if st.attempts == 0 {
		t.Fatal("the store was never asked to save anything — this test would pass without exercising " +
			"the loop it exists to check, which is how the first version of it asserted nothing")
	}
	if len(got) != 0 {
		t.Errorf("returned %d finding(s) the store rejected. Each is appended to `current`, opens an "+
			"incident, and is then absent from /issues — the two views disagree with no explanation.",
			len(got))
	}
}

// The control: with a working store the same run DOES return its findings, so this cannot become a
// way to drop findings silently.
func TestSyncOSINT_ReturnsWhatItStored(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	_ = mem.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = mem.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "domain", Target: "acme.example"})

	n := 0
	svc := &Service{
		Store: mem,
		NewID: func() string { n++; return "f" + itoa(n) },
		OSINTFetcher: func(context.Context, string) ([]byte, error) {
			return []byte(`[{"name_value":"forgotten-staging.acme.example"}]`), nil
		},
	}
	if got, _ := svc.syncOSINT(ctx, "t1"); len(got) == 0 {
		t.Fatal("a working store must still yield the finding — otherwise the fix trades a view " +
			"mismatch for losing the detection entirely")
	}
}
