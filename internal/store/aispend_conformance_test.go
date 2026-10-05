package store

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// AI spend is APPEND-ONLY: two runs of the same kind and scope are two rows (the defect it replaces was a
// record keyed kind:scope, so a re-run overwrote the last and the budget saw one run). Ordered
// oldest-first, isolated per tenant, and durable across a reopen of the file store.
func TestStore_AISpendAppendOnlyAndIsolated(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			ctx := context.Background()
			t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
			for i, e := range []platform.AISpend{
				{ID: "s2", TenantID: "t1", At: t0.Add(time.Hour), Kind: "triage", Surface: "estate", USD: 0.4, CostKnown: true},
				{ID: "s1", TenantID: "t1", At: t0, Kind: "triage", Surface: "estate", USD: 0.5, CostKnown: true},
				{ID: "x1", TenantID: "t2", At: t0, Kind: "cloud", Surface: "cloud", USD: 9},
			} {
				if err := s.PutAISpend(ctx, e); err != nil {
					t.Fatalf("%s put %d: %v", f.name, i, err)
				}
			}
			got, err := s.ListAISpend(ctx, "t1")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 {
				t.Fatalf("%s: two runs of the same kind must be two rows, got %d", f.name, len(got))
			}
			if got[0].ID != "s1" || got[1].ID != "s2" {
				t.Errorf("%s: must be oldest-first: %v, %v", f.name, got[0].ID, got[1].ID)
			}
			if got[0].USD != 0.5 || !got[0].CostKnown || got[0].Surface != "estate" {
				t.Errorf("%s: fields not round-tripped: %+v", f.name, got[0])
			}
			if other, _ := s.ListAISpend(ctx, "t2"); len(other) != 1 {
				t.Errorf("%s: tenant isolation broken: %+v", f.name, other)
			}
		})
	}
}
