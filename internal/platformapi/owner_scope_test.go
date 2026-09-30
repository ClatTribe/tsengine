package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ownerScopeDeps is a workspace with one owner and one member, each signed in.
func ownerScopeDeps(t *testing.T) (Deps, *store.Memory) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []platform.User{
		{ID: "u-own", TenantID: "t1", Email: "ada@acme.io", Role: platform.RoleOwner},
		{ID: "u-mem", TenantID: "t1", Email: "bo@acme.io", Role: platform.RoleMember},
	} {
		if err := st.PutUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok := "sess-" + strings.TrimPrefix(u.ID, "u-")
		if err := st.PutSession(ctx, platform.Session{Token: tok, UserID: u.ID, TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	return Deps{Store: st}, st
}

// THE GUARD THAT MAKES THE OWNER LINE REAL. Every route in api.go goes through the auth middleware
// with a MEMBER session and an OWNER session: the member must be refused exactly the owner-only
// routes, and the owner must be refused none of them. Enumerated rather than sampled, because the
// route this would miss is the one where a member quietly changes a setting the owner relies on.
func TestMemberIsRefusedExactlyTheOwnerOnlyRoutes(t *testing.T) {
	routes := registeredRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("only %d routes parsed from api.go — the guard is covering almost nothing", len(routes))
	}
	d, _ := ownerScopeDeps(t)
	wild := regexp.MustCompile(`\{[^}]+\}`)

	refused := 0
	for _, rt := range routes {
		path := wild.ReplaceAllString(rt.path, "x1")
		for _, who := range []string{"mem", "own"} {
			called := false
			h := d.auth(func(http.ResponseWriter, *http.Request, string) { called = true })
			req := httptest.NewRequest(rt.method, path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer sess-"+who)
			rec := httptest.NewRecorder()
			h(rec, req)

			ownerOnly := ownerOnlyRoute(rt.method, path)
			switch {
			case who == "own" && !called:
				t.Errorf("the OWNER was refused %s %s (%d) — the owner gate must never lock out the owner", rt.method, rt.path, rec.Code)
			case who == "mem" && ownerOnly && called:
				t.Errorf("a MEMBER reached owner-only %s %s", rt.method, rt.path)
			case who == "mem" && ownerOnly && (rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "owner_only")):
				t.Errorf("%s %s refused a member with %d %s, want 403 owner_only", rt.method, rt.path, rec.Code, rec.Body.String())
			case who == "mem" && !ownerOnly && !called:
				t.Errorf("a MEMBER was refused %s %s (%d) — members keep the day-to-day work", rt.method, rt.path, rec.Code)
			}
			if who == "mem" && ownerOnly && !called {
				refused++
			}
		}
	}
	// A floor, so a matcher that stopped matching cannot pass by refusing nothing: the settings prefix
	// alone is more than this.
	if refused < 25 {
		t.Fatalf("members were refused only %d routes — the owner gate has stopped matching", refused)
	}
}

// The classification of the acts that matter most, pinned by name. The route walk proves the gate
// enforces whatever ownerOnlyRoute says; this proves ownerOnlyRoute says the right thing about them.
func TestOwnerOnlyClassification(t *testing.T) {
	cases := []struct {
		method, path string
		ownerOnly    bool
	}{
		// governance — owner only
		{http.MethodPut, "/v1/settings/llm", true},
		{http.MethodPut, "/v1/settings/notifications", true},
		{http.MethodPut, "/v1/settings/jira", true},
		{http.MethodPut, "/v1/settings/trust-center", true},
		{http.MethodPost, "/v1/settings/trust-center/revoke-link", true},
		{http.MethodPut, "/v1/settings/some-setting-added-next-year", true}, // prefix: closed by default
		{http.MethodDelete, "/v1/connections/c1", true},
		{http.MethodPost, "/v1/connections/c1/cloud-remediation", true},
		{http.MethodPost, "/v1/maintenance-windows", true},
		{http.MethodPost, "/v1/trust-requests/r1/decision", true},
		{http.MethodPost, "/v1/exclusions", true},
		{http.MethodPost, "/v1/contacts", true},
		{http.MethodPost, "/v1/practitioners", true},
		{http.MethodPost, "/v1/program/p1/publish", true},
		{http.MethodPost, "/v1/products/scope", true},
		// the cautious direction, and the day-to-day work — open to members
		{http.MethodGet, "/v1/settings/llm", false},
		{http.MethodPost, "/v1/killswitch", false},                // direction checked in the handler
		{http.MethodPost, "/v1/connections/c1/quarantine", false}, // ditto
		{http.MethodPost, "/v1/issues/ignore", false},             // ditto
		{http.MethodDelete, "/v1/maintenance-windows/m1", false},
		{http.MethodPost, "/v1/exclusions/delete", false},
		{http.MethodPost, "/v1/approvals/a1", false},
		{http.MethodPost, "/v1/rescan", false},
		{http.MethodPost, "/v1/program/p1/ack", false},
		{http.MethodGet, "/v1/products/p1", false},
		{http.MethodPost, "/v1/products/p1/extra", false}, // exact segment count, not a prefix
	}
	for _, c := range cases {
		if got := ownerOnlyRoute(c.method, c.path); got != c.ownerOnly {
			t.Errorf("ownerOnlyRoute(%s %s) = %v, want %v", c.method, c.path, got, c.ownerOnly)
		}
	}
}

// A listed route that is not registered guards nothing — a typo, or a route renamed out from under the
// list. Fail rather than carry an entry that reads as protection.
func TestEveryOwnerOnlyEntryIsARealRoute(t *testing.T) {
	registered := map[string]bool{}
	for _, rt := range registeredRoutes(t) {
		registered[rt.method+" "+rt.path] = true
	}
	for _, o := range ownerOnlyRoutes {
		if !registered[o.method+" "+o.path] {
			t.Errorf("ownerOnlyRoutes lists %s %s, which api.go does not register — it protects nothing", o.method, o.path)
		}
	}
}

// memberOwnerCall runs one request through the real auth middleware as the given seat.
func memberOwnerCall(d Deps, h func(http.ResponseWriter, *http.Request, string), who, method, path, body string, pathVals map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range pathVals {
		req.SetPathValue(k, v)
	}
	req.Header.Set("Authorization", "Bearer sess-"+who)
	rec := httptest.NewRecorder()
	d.auth(h)(rec, req)
	return rec
}

func isOwnerOnlyRefusal(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "owner_only")
}

// Anyone may pull the brake; only the owner may release it.
func TestKillSwitch_MemberMayHaltButNotResume(t *testing.T) {
	d, st := ownerScopeDeps(t)
	ctx := context.Background()

	if rec := memberOwnerCall(d, d.handleKillSwitch, "mem", http.MethodPost, "/v1/killswitch", `{"halted":true}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("a member halting automation: %d %s — the cautious direction must stay open", rec.Code, rec.Body)
	}
	rec := memberOwnerCall(d, d.handleKillSwitch, "mem", http.MethodPost, "/v1/killswitch", `{"halted":false}`, nil)
	if !isOwnerOnlyRefusal(rec) {
		t.Fatalf("a member resuming halted automation: %d %s, want 403 owner_only", rec.Code, rec.Body)
	}
	if tn, _ := st.GetTenant(ctx, "t1"); !tn.AgentsHalted {
		t.Fatal("the refused resume still released the kill-switch")
	}
	if rec := memberOwnerCall(d, d.handleKillSwitch, "own", http.MethodPost, "/v1/killswitch", `{"halted":false}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("the owner resuming: %d %s", rec.Code, rec.Body)
	}
	if tn, _ := st.GetTenant(ctx, "t1"); tn.AgentsHalted {
		t.Fatal("the owner's resume did not take")
	}
}

func TestQuarantine_MemberMayQuarantineButNotRestore(t *testing.T) {
	d, st := ownerScopeDeps(t)
	ctx := context.Background()
	if err := st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive}); err != nil {
		t.Fatal(err)
	}
	pv := map[string]string{"id": "c1"}
	status := func() string {
		cs, _ := st.ListConnections(ctx, "t1")
		return cs[0].Status
	}

	if rec := memberOwnerCall(d, d.handleQuarantineConnection, "mem", http.MethodPost, "/v1/connections/c1/quarantine", `{"quarantined":true}`, pv); rec.Code != http.StatusOK {
		t.Fatalf("a member quarantining: %d %s", rec.Code, rec.Body)
	}
	rec := memberOwnerCall(d, d.handleQuarantineConnection, "mem", http.MethodPost, "/v1/connections/c1/quarantine", `{"quarantined":false}`, pv)
	if !isOwnerOnlyRefusal(rec) {
		t.Fatalf("a member restoring a quarantined connection: %d %s, want 403 owner_only", rec.Code, rec.Body)
	}
	if status() != platform.ConnQuarantined {
		t.Fatal("the refused restore still reactivated the connection")
	}
	if rec := memberOwnerCall(d, d.handleQuarantineConnection, "own", http.MethodPost, "/v1/connections/c1/quarantine", `{"quarantined":false}`, pv); rec.Code != http.StatusOK {
		t.Fatalf("the owner restoring: %d %s", rec.Code, rec.Body)
	}
	if status() != platform.ConnActive {
		t.Fatal("the owner's restore did not take")
	}
}

// "Not real" is triage; "real, and we are living with it" is a risk decision.
func TestIgnore_MemberMayMarkFalsePositiveButNotAcceptRisk(t *testing.T) {
	d, st := ownerScopeDeps(t)
	ctx := context.Background()
	call := func(who, body string) *httptest.ResponseRecorder {
		return memberOwnerCall(d, d.handleIgnoreIssue, who, http.MethodPost, "/v1/issues/ignore", body, nil)
	}

	if rec := call("mem", `{"key":"k-fp","reason":"false_positive"}`); rec.Code != http.StatusOK {
		t.Fatalf("a member marking a false positive: %d %s", rec.Code, rec.Body)
	}
	for _, body := range []string{
		`{"key":"k-ar","reason":"accepted_risk"}`,
		`{"key":"k-wf","reason":"wont_fix"}`,
		`{"key":"k-none"}`, // no reason defaults to accepted_risk — must not be a way round the gate
	} {
		if rec := call("mem", body); !isOwnerOnlyRefusal(rec) {
			t.Errorf("a member suppressing %s: %d %s, want 403 owner_only", body, rec.Code, rec.Body)
		}
	}
	rules, _ := st.ListIgnoreRules(ctx, "t1")
	if len(rules) != 1 || rules[0].IssueKey != "k-fp" {
		t.Fatalf("only the false positive may have been stored, got %+v", rules)
	}
	if rec := call("own", `{"key":"k-ar","reason":"accepted_risk"}`); rec.Code != http.StatusOK {
		t.Fatalf("the owner accepting a risk: %d %s", rec.Code, rec.Body)
	}
}

func TestRiskDecision_MemberMayTreatButNotAccept(t *testing.T) {
	d, st := ownerScopeDeps(t)
	ctx := context.Background()
	if err := st.PutRisk(ctx, platform.Risk{ID: "r1", TenantID: "t1", Title: "SQL injection", Likelihood: 3, Impact: 4}); err != nil {
		t.Fatal(err)
	}
	pv := map[string]string{"id": "r1"}
	call := func(who, body string) *httptest.ResponseRecorder {
		return memberOwnerCall(d, d.handleDecideRisk, who, http.MethodPost, "/v1/risks/r1/decision", body, pv)
	}

	if rec := call("mem", `{"treatment":" Accept ","owner":"Bo","rationale":"low exposure"}`); !isOwnerOnlyRefusal(rec) {
		t.Fatalf("a member accepting a risk: %d %s, want 403 owner_only", rec.Code, rec.Body)
	}
	if rec := call("mem", `{"treatment":"mitigate","owner":"Bo","rationale":"patch this sprint"}`); rec.Code != http.StatusOK {
		t.Fatalf("a member committing to mitigate: %d %s", rec.Code, rec.Body)
	}
	if rec := call("own", `{"treatment":"accept","owner":"Ada","rationale":"compensating control"}`); rec.Code != http.StatusOK {
		t.Fatalf("the owner accepting: %d %s", rec.Code, rec.Body)
	}
}
