package cloudsnap

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestStores_RoundTripAndIsolation(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		mk   func(t *testing.T) Store
	}{
		{"mem", func(*testing.T) Store { return NewMemStore() }},
		{"file", func(t *testing.T) Store {
			s, err := NewFileStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.mk(t)

			// missing → ok=false, no error.
			if _, ok, err := s.Get(ctx, "t1"); err != nil || ok {
				t.Fatalf("empty get: ok=%v err=%v", ok, err)
			}

			// round-trip per tenant.
			must(t, s.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(`{"a":1}`), Prowler: []types.Finding{{ID: "f1"}}, CapturedAt: time.Unix(1, 0).UTC()}))
			must(t, s.Put(ctx, Snapshot{TenantID: "t2", Inventory: json.RawMessage(`{"b":2}`)}))

			got, ok, err := s.Get(ctx, "t1")
			if err != nil || !ok {
				t.Fatalf("get t1: ok=%v err=%v", ok, err)
			}
			if string(got.Inventory) != `{"a":1}` || len(got.Prowler) != 1 || got.TenantID != "t1" {
				t.Errorf("t1 round-trip mismatch: %+v", got)
			}

			// ISOLATION: t1's read never returns t2's data, and vice-versa.
			if g2, _, _ := s.Get(ctx, "t2"); string(g2.Inventory) != `{"b":2}` {
				t.Errorf("t2 isolation: got %s", g2.Inventory)
			}

			// latest-wins.
			must(t, s.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(`{"a":99}`)}))
			if g, _, _ := s.Get(ctx, "t1"); string(g.Inventory) != `{"a":99}` {
				t.Errorf("latest-wins failed: %s", g.Inventory)
			}

			// empty tenant id is rejected.
			if err := s.Put(ctx, Snapshot{Inventory: json.RawMessage(`{}`)}); err == nil {
				t.Error("empty tenant id should error")
			}
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
