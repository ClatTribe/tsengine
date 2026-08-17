package ratelimit

import (
	"testing"
	"time"
)

// A nil limiter and a non-positive allowance both allow everything — the fail-open
// contract the middleware relies on.
func TestNilAndUnlimitedAllowEverything(t *testing.T) {
	var l *Limiter // nil
	for i := 0; i < 1000; i++ {
		if !l.Allow("t", 60) {
			t.Fatal("nil limiter must allow everything")
		}
	}
	l = New()
	for i := 0; i < 1000; i++ {
		if !l.Allow("t", 0) {
			t.Fatal("perMinute<=0 must be unlimited")
		}
	}
}

// A tenant that exceeds its per-minute allowance in a burst is throttled once the
// burst is spent — and the limit is PER KEY, so one tenant's exhaustion never affects
// another.
func TestPerTenantIsolationAndThrottle(t *testing.T) {
	now := time.Unix(0, 0)
	l := &Limiter{buckets: map[string]*bucket{}, now: func() time.Time { return now }}
	const perMin = 60 // burst 60, refill 1/s

	// Tenant A spends its whole burst instantly.
	for i := 0; i < 60; i++ {
		if !l.Allow("A", perMin) {
			t.Fatalf("A request %d should be within the burst", i)
		}
	}
	// The 61st (same instant) is throttled.
	if l.Allow("A", perMin) {
		t.Fatal("A should be throttled after spending its full burst")
	}
	// Tenant B is completely unaffected — the limit is per key.
	if !l.Allow("B", perMin) {
		t.Fatal("B must not be throttled by A's usage")
	}

	// After a second, A has refilled one token.
	now = now.Add(time.Second)
	if !l.Allow("A", perMin) {
		t.Fatal("A should have one refilled token after 1s")
	}
	if l.Allow("A", perMin) {
		t.Fatal("A should be throttled again immediately after")
	}
}

// A plan change (different perMinute for the same key) rebuilds the bucket rather than
// keeping the old rate — so an upgrade takes effect immediately.
func TestRebuildOnAllowanceChange(t *testing.T) {
	now := time.Unix(0, 0)
	l := &Limiter{buckets: map[string]*bucket{}, now: func() time.Time { return now }}
	// Spend a tiny allowance.
	l.Allow("t", 1) // burst 1
	if l.Allow("t", 1) {
		t.Fatal("second request at perMin=1 should be throttled")
	}
	// Upgrade to a big allowance → fresh bucket, immediately allowed.
	if !l.Allow("t", 600) {
		t.Fatal("after upgrading the allowance, the request should pass on the fresh bucket")
	}
}

// Idle buckets are swept so memory is bounded under many tenants.
func TestIdleSweep(t *testing.T) {
	now := time.Unix(0, 0)
	l := &Limiter{buckets: map[string]*bucket{}, now: func() time.Time { return now }}
	l.Allow("gone", 60)
	if len(l.buckets) != 1 {
		t.Fatalf("want 1 bucket, got %d", len(l.buckets))
	}
	// Advance past the idle TTL + a sweep interval and touch a different key to trigger a sweep.
	now = now.Add(idleTTL + 2*sweepEvery)
	l.Allow("fresh", 60)
	if _, stale := l.buckets["gone"]; stale {
		t.Error("an idle bucket should have been swept")
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Error("the fresh bucket must survive")
	}
}
