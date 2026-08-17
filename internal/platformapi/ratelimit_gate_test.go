package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/ratelimit"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// authedGet fires an authenticated GET against a handler and returns the status.
func authedGet(h http.Handler, path, tenant string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer platform-tok")
	req.Header.Set("X-Tenant-ID", tenant)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func rlDeps(t *testing.T, plan string) (http.Handler, string) {
	t.Helper()
	st := store.NewMemory()
	tid := "t-rl-" + plan
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: tid, Name: "Acme", Plan: plan}); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st, Token: "platform-tok", RateLimiter: ratelimit.New()}
	return NewHandler(d), tid
}

// A Free tenant that floods the API is eventually throttled with 429 — the fair-use
// ceiling protects the shared service from one tenant's runaway automation.
func TestRateLimit_FreeTenantThrottled(t *testing.T) {
	h, tid := rlDeps(t, platform.PlanFree) // APIRatePerMin 120 → burst 120
	got429 := false
	for i := 0; i < 200; i++ { // exceed the burst within one instant
		if authedGet(h, "/v1/findings", tid) == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("a Free tenant flooding the API was never rate-limited (429) — the fair-use ceiling isn't enforced")
	}
}

// An Enterprise tenant is unmetered (APIRatePerMin 0), so the same flood never 429s.
// This is the "paid customers get headroom" half — and it proves the Free test above
// isn't just the limiter firing on everyone.
func TestRateLimit_EnterpriseUnmetered(t *testing.T) {
	h, tid := rlDeps(t, platform.PlanEnterprise)
	for i := 0; i < 500; i++ {
		if code := authedGet(h, "/v1/findings", tid); code == http.StatusTooManyRequests {
			t.Fatalf("an Enterprise (unmetered) tenant was rate-limited at request %d", i)
		}
	}
}

// With no limiter wired, nothing is throttled — fail-open, the test/default behaviour.
func TestRateLimit_DisabledWhenNoLimiter(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme", Plan: platform.PlanFree})
	h := NewHandler(Deps{Store: st, Token: "platform-tok"}) // RateLimiter nil
	for i := 0; i < 500; i++ {
		if authedGet(h, "/v1/findings", "t1") == http.StatusTooManyRequests {
			t.Fatal("no limiter wired, yet a request was throttled — the gate must be fail-open")
		}
	}
}

// One tenant hitting its ceiling must NOT throttle another tenant — isolation at the
// HTTP layer, not just in the limiter unit.
func TestRateLimit_TenantIsolationAtTheGate(t *testing.T) {
	st := store.NewMemory()
	for _, id := range []string{"a", "b"} {
		_ = st.PutTenant(context.Background(), platform.Tenant{ID: id, Name: id, Plan: platform.PlanFree})
	}
	h := NewHandler(Deps{Store: st, Token: "platform-tok", RateLimiter: ratelimit.New()})
	// Exhaust tenant a.
	for i := 0; i < 200; i++ {
		authedGet(h, "/v1/findings", "a")
	}
	// Tenant b's first request must still succeed (not 429).
	if code := authedGet(h, "/v1/findings", "b"); code == http.StatusTooManyRequests {
		t.Error("tenant b was throttled by tenant a's flood — tenant isolation broken at the gate")
	}
}
