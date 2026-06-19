package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The Store conformance suite — the full behavioral contract every Store impl must
// honor, run against EACH impl. The two guarantees it pins are (1) every entity
// round-trips per tenant, and (2) no tenant-scoped read EVER crosses the tenant
// boundary — §18.2 invariant 2, the platform's security boundary. The file-backed
// (production-durable) store is held to the same bar as Memory, and a future SQL /
// Postgres store plugs into this same suite to prove parity before it ships.

type storeFactory struct {
	name string
	open func(t *testing.T) Store
}

func factories() []storeFactory {
	return []storeFactory{
		{"memory", func(*testing.T) Store { return NewMemory() }},
		{"file", func(t *testing.T) Store {
			s, err := OpenFile(filepath.Join(t.TempDir(), "store.json"))
			if err != nil {
				t.Fatalf("open file store: %v", err)
			}
			return s
		}},
		{"sqlite", func(t *testing.T) Store {
			s, err := OpenSQLite(filepath.Join(t.TempDir(), "store.db"))
			if err != nil {
				t.Fatalf("open sqlite store: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		}},
	}
}

// seedTenant writes exactly one of every tenant-scoped entity for tid.
func seedTenant(ctx context.Context, t *testing.T, s Store, tid string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("seed %s: %v", tid, err)
		}
	}
	must(s.PutTenant(ctx, platform.Tenant{ID: tid, Name: tid}))
	must(s.PutConnection(ctx, platform.Connection{ID: tid + "-c", TenantID: tid, Kind: platform.ConnGitHub, Status: platform.ConnActive}))
	must(s.PutAsset(ctx, platform.Asset{ID: tid + "-a", TenantID: tid, Type: "repository", Target: tid + "/repo"}))
	must(s.PutEngagement(ctx, platform.Engagement{ID: tid + "-e", TenantID: tid}))
	must(s.PutFinding(ctx, tid, types.Finding{ID: tid + "-f", Severity: types.SeverityHigh}))
	must(s.PutAction(ctx, platform.Action{ID: tid + "-act", TenantID: tid, Status: platform.ActPendingApproval, Tier: 2}))
	must(s.UpsertControlState(ctx, platform.ControlState{TenantID: tid, Framework: "soc2", ControlID: "CC6.1", State: platform.ControlGap}))
	must(s.PutIncident(ctx, platform.Incident{ID: tid + "-i", TenantID: tid, Status: platform.IncidentOpen}))
	must(s.PutReviewRequest(ctx, platform.ReviewRequest{ID: tid + "-r", TenantID: tid, Status: platform.ReviewOpen}))
	must(s.ReplaceThirdPartyApps(ctx, tid, "gworkspace", []platform.ThirdPartyApp{{TenantID: tid, Provider: "gworkspace", AppID: tid + "-app"}}))
}

func TestStoreConformance(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.open(t)
			seedTenant(ctx, t, s, "t1")
			seedTenant(ctx, t, s, "t2")

			// Each tenant-scoped list returns exactly its owner's one item, and the
			// returned item carries the owner's id — never the other tenant's.
			isolated := func(name, owner string, ids []string) {
				t.Helper()
				if len(ids) != 1 {
					t.Fatalf("%s[%s]: want 1 item, got %d (%v)", name, owner, len(ids), ids)
				}
				for _, id := range ids {
					if !hasPrefix(id, owner+"-") && id != owner {
						t.Errorf("ISOLATION %s[%s]: saw foreign id %q", name, owner, id)
					}
				}
			}

			for _, tid := range []string{"t1", "t2"} {
				conns, err := s.ListConnections(ctx, tid)
				orFail(t, err)
				isolated("connections", tid, ids(conns, func(c platform.Connection) string { return c.ID }))

				assets, err := s.ListAssets(ctx, tid)
				orFail(t, err)
				isolated("assets", tid, ids(assets, func(a platform.Asset) string { return a.ID }))

				engs, err := s.ListEngagements(ctx, tid)
				orFail(t, err)
				isolated("engagements", tid, ids(engs, func(e platform.Engagement) string { return e.ID }))

				finds, err := s.ListFindings(ctx, tid, FindingFilter{})
				orFail(t, err)
				isolated("findings", tid, ids(finds, func(f types.Finding) string { return f.ID }))

				appr, err := s.PendingApprovals(ctx, tid)
				orFail(t, err)
				isolated("approvals", tid, ids(appr, func(a platform.Action) string { return a.ID }))

				post, err := s.Posture(ctx, tid, "soc2")
				orFail(t, err)
				if len(post) != 1 || post[0].TenantID != tid {
					t.Errorf("ISOLATION posture[%s]: %+v", tid, post)
				}

				incs, err := s.ListIncidents(ctx, tid)
				orFail(t, err)
				isolated("incidents", tid, ids(incs, func(i platform.Incident) string { return i.ID }))

				revs, err := s.ListReviewRequests(ctx, tid)
				orFail(t, err)
				isolated("reviews", tid, ids(revs, func(r platform.ReviewRequest) string { return r.ID }))

				apps, err := s.ListThirdPartyApps(ctx, tid)
				orFail(t, err)
				if len(apps) != 1 || apps[0].TenantID != tid {
					t.Errorf("ISOLATION apps[%s]: %+v", tid, apps)
				}

				// GetAction is tenant-scoped: t1's action id is invisible to t2.
				if _, err := s.GetAction(ctx, tid, tid+"-act"); err != nil {
					t.Errorf("GetAction[%s]: %v", tid, err)
				}
				other := "t2"
				if tid == "t2" {
					other = "t1"
				}
				if _, err := s.GetAction(ctx, tid, other+"-act"); err == nil {
					t.Errorf("ISOLATION GetAction[%s] returned %s's action", tid, other)
				}
			}

			// ListTenants is global (not tenant-scoped) — both are present.
			tens, err := s.ListTenants(ctx)
			orFail(t, err)
			if len(tens) != 2 {
				t.Errorf("ListTenants: want 2, got %d", len(tens))
			}
		})
	}
}

func ids[T any](xs []T, id func(T) string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, id(x))
	}
	return out
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func orFail(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
}
