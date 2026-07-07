package store

import (
	"context"
	"os"
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
	fs := []storeFactory{
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
	// Postgres runs through the SAME conformance suite when TEST_POSTGRES_URL points at a throwaway
	// database (e.g. a Supabase/Neon/local-docker test DB). Skipped otherwise — the impl is a mechanical
	// port of the SQLite store, so the contract is identical; this proves it against a real Postgres.
	if dsn := os.Getenv("TEST_POSTGRES_URL"); dsn != "" {
		fs = append(fs, storeFactory{"postgres", func(t *testing.T) Store {
			p, err := OpenPostgres(dsn)
			if err != nil {
				t.Fatalf("open postgres store: %v", err)
			}
			// Clean slate: each conformance run starts empty (Postgres is a shared DB, not a temp dir).
			for _, tbl := range []string{"tenants", "connections", "assets", "engagements", "findings", "actions",
				"controls", "incidents", "risks", "audits", "policies", "ignores", "exclusions", "runtimeevts",
				"pentests", "reviews", "apps", "users", "sessions", "operators", "opsessions"} {
				if _, err := p.db.ExecContext(context.Background(), "TRUNCATE TABLE "+tbl); err != nil {
					t.Fatalf("truncate %s: %v", tbl, err)
				}
			}
			t.Cleanup(func() { _ = p.Close() })
			return p
		}})
	}
	return fs
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
	must(s.PutRisk(ctx, platform.Risk{ID: tid + "-rk", TenantID: tid, Title: "r", Status: platform.RiskOpen}))
	must(s.PutAIAnalysis(ctx, platform.AIAnalysis{ID: tid + "-ai", TenantID: tid, Kind: "triage", Summary: "s"}))
	must(s.PutAuditEngagement(ctx, platform.AuditEngagement{ID: tid + "-au", TenantID: tid, Framework: "soc2", Status: platform.AuditPlanning}))
	must(s.PutPolicy(ctx, platform.Policy{ID: tid + "-pol", TenantID: tid, Name: "p", Status: platform.PolicyDraft}))
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

				allActs, err := s.ListActions(ctx, tid)
				orFail(t, err)
				isolated("actions", tid, ids(allActs, func(a platform.Action) string { return a.ID }))

				post, err := s.Posture(ctx, tid, "soc2")
				orFail(t, err)
				if len(post) != 1 || post[0].TenantID != tid {
					t.Errorf("ISOLATION posture[%s]: %+v", tid, post)
				}

				incs, err := s.ListIncidents(ctx, tid)
				orFail(t, err)
				isolated("incidents", tid, ids(incs, func(i platform.Incident) string { return i.ID }))

				rks, err := s.ListRisks(ctx, tid)
				orFail(t, err)
				isolated("risks", tid, ids(rks, func(r platform.Risk) string { return r.ID }))

				ais, err := s.ListAIAnalyses(ctx, tid)
				orFail(t, err)
				isolated("ai_analyses", tid, ids(ais, func(a platform.AIAnalysis) string { return a.ID }))

				aus, err := s.ListAuditEngagements(ctx, tid)
				orFail(t, err)
				isolated("audits", tid, ids(aus, func(a platform.AuditEngagement) string { return a.ID }))

				pols, err := s.ListPolicies(ctx, tid)
				orFail(t, err)
				isolated("policies", tid, ids(pols, func(p platform.Policy) string { return p.ID }))

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

			// DeleteConnection is tenant-scoped: removing t1's connection leaves t2's intact.
			orFail(t, s.DeleteConnection(ctx, "t1", "t1-c"))
			c1, err := s.ListConnections(ctx, "t1")
			orFail(t, err)
			if len(c1) != 0 {
				t.Errorf("DeleteConnection: t1 want 0 connections, got %d", len(c1))
			}
			c2, err := s.ListConnections(ctx, "t2")
			orFail(t, err)
			if len(c2) != 1 || c2[0].ID != "t2-c" {
				t.Errorf("ISOLATION DeleteConnection: t2's connection affected: %+v", c2)
			}
			// Deleting an absent id is a no-op (not an error).
			orFail(t, s.DeleteConnection(ctx, "t2", "does-not-exist"))
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

// DeleteSessionsForUser revokes exactly one user's sessions (the credential-change/reset kill step),
// leaving other users' sessions intact — proven against every Store impl.
func TestStore_DeleteSessionsForUser(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("%s: %v", f.name, err)
				}
			}
			must(s.PutSession(ctx, platform.Session{Token: "a1", UserID: "u1", TenantID: "t1"}))
			must(s.PutSession(ctx, platform.Session{Token: "a2", UserID: "u1", TenantID: "t1"}))
			must(s.PutSession(ctx, platform.Session{Token: "b1", UserID: "u2", TenantID: "t1"}))

			must(s.DeleteSessionsForUser(ctx, "u1"))

			for _, tok := range []string{"a1", "a2"} {
				if _, err := s.GetSession(ctx, tok); err == nil {
					t.Errorf("%s: u1 session %q should be revoked", f.name, tok)
				}
			}
			if _, err := s.GetSession(ctx, "b1"); err != nil {
				t.Errorf("%s: u2's session must survive, got %v", f.name, err)
			}
		})
	}
}
