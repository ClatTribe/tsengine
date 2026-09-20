package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// THE GUARD THAT MAKES THE ALLOWLIST REAL.
//
// It drives EVERY route registered in api.go through the auth middleware with an employee session
// and asserts each is refused unless it is on the allowlist. Without it the allowlist is a comment:
// somebody adds an endpoint, nobody thinks about employees, and the seat silently widens. Written
// as an enumeration rather than a sample for exactly that reason — the route this misses is the one
// that leaks.
//
// FAILS rather than skips when api.go moves or the pattern matches nothing (§14.2 rule 6): a guard
// that cannot see its subject is indistinguishable from one that passed.
func TestEmployeeSeatIsRefusedEverythingItIsNotExplicitlyGiven(t *testing.T) {
	routes := registeredRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("only %d routes parsed from api.go — the pattern has stopped matching and this guard "+
			"is covering almost nothing", len(routes))
	}

	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	emp := platform.User{ID: "u-emp", TenantID: "t1", Email: "casey@acme.io", Role: platform.RoleEmployee}
	if err := st.PutUser(ctx, emp); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession(ctx, platform.Session{Token: "sess-emp", UserID: emp.ID, TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st}

	var reached []string
	for _, rt := range routes {
		// A concrete path for the wildcard routes; the id never matters to the gate.
		path := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(rt.path, "x1")
		called := false
		h := d.auth(func(http.ResponseWriter, *http.Request, string) { called = true })

		req := httptest.NewRequest(rt.method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer sess-emp")
		rec := httptest.NewRecorder()
		h(rec, req)

		allowed := employeeMayReach(rt.method, path)
		switch {
		case allowed && !called:
			t.Errorf("%s %s is on the employee allowlist but the gate refused it (%d)", rt.method, path, rec.Code)
		case !allowed && called:
			reached = append(reached, rt.method+" "+rt.path)
		case !allowed && rec.Code != http.StatusForbidden:
			t.Errorf("%s %s refused an employee with %d, want 403", rt.method, path, rec.Code)
		}
	}
	if len(reached) > 0 {
		t.Errorf("an employee seat reached %d endpoint(s) that are not on the allowlist:\n  %s\n\n"+
			"The seat exists so a colleague can be asked to do their training without being handed "+
			"the security estate. Add the route to employeeAllowed only if an employee genuinely "+
			"needs it for their OWN training or policy acknowledgements.",
			len(reached), strings.Join(reached, "\n  "))
	}
}

// The allowlist must not admit anything by accident — the program routes are the risk, since they
// share a prefix with publishing a policy, which is an owner's act.
func TestEmployeeAllowlistAdmitsAckButNotPublish(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/v1/training", true},
		{http.MethodPost, "/v1/training/complete", true},
		// Recording that a COLLEAGUE trained elsewhere is an administrative act about somebody else.
		{http.MethodPost, "/v1/training/record", false},
		{http.MethodGet, "/v1/program", true},
		{http.MethodPost, "/v1/program/p1/ack", true},
		{http.MethodPost, "/v1/program/p1/publish", false},
		{http.MethodPost, "/v1/program/seed", false},
		{http.MethodGet, "/v1/findings", false},
		{http.MethodGet, "/v1/pentest", false},
		{http.MethodGet, "/v1/system-state", false},
		// Method matters: a read route must not admit a write to the same path.
		{http.MethodPost, "/v1/training", false},
	}
	for _, c := range cases {
		if got := employeeMayReach(c.method, c.path); got != c.want {
			t.Errorf("employeeMayReach(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// An employee may be invited, and the invite path must keep refusing an owner seat and an unknown
// role — a typo must not silently become a member.
func TestInviteAcceptsEmployeeButStillRefusesOwnerAndNonsense(t *testing.T) {
	for _, c := range []struct {
		role string
		want int
	}{
		{"employee", http.StatusCreated},
		{"auditor", http.StatusCreated},
		{"member", http.StatusCreated},
		{"owner", http.StatusBadRequest},
		{"admin", http.StatusBadRequest},
	} {
		ctx := context.Background()
		st := store.NewMemory()
		if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
			t.Fatal(err)
		}
		owner := platform.User{ID: "u1", TenantID: "t1", Email: "ada@acme.io", Role: platform.RoleOwner}
		if err := st.PutUser(ctx, owner); err != nil {
			t.Fatal(err)
		}
		d := Deps{Store: st, NewID: func() string { return "u-new" }}
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/invite",
			strings.NewReader(`{"email":"casey@acme.io","role":"`+c.role+`"}`))
		rec := httptest.NewRecorder()
		d.handleInvite(rec, req, platform.Session{UserID: owner.ID, TenantID: "t1"})
		if rec.Code != c.want {
			t.Errorf("invite role=%q → %d, want %d (%s)", c.role, rec.Code, c.want, rec.Body.String())
		}
	}
}

type routeDecl struct{ method, path string }

// registeredRoutes parses api.go for its mux registrations. Reading the source rather than a
// hand-kept list is the point: a list would drift the moment somebody adds a route, which is
// precisely the event this guard exists to catch.
func registeredRoutes(t *testing.T) []routeDecl {
	t.Helper()
	b, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("cannot read api.go: %v — if the routes moved, move this guard with them rather "+
			"than letting it cover nothing", err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("(GET|POST|PUT|DELETE|PATCH) ([^"]+)"`)
	ms := re.FindAllStringSubmatch(string(b), -1)
	out := make([]routeDecl, 0, len(ms))
	for _, m := range ms {
		out = append(out, routeDecl{method: m[1], path: m[2]})
	}
	return out
}
