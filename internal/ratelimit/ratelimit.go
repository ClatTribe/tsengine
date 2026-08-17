// Package ratelimit is a per-tenant request rate limiter for the platform API.
//
// WHY: the authenticated /v1 API had no per-tenant throttling, so one tenant's
// runaway automation (a misconfigured CI loop, a retry storm, or abuse) could
// exhaust the shared service for everyone. This adds a fair-use ceiling keyed by
// tenant, with the allowance scaled by plan (paid tiers get more headroom), so a
// single tenant cannot degrade the platform and paying customers get a guaranteed
// throughput floor.
//
// It is deliberately a SERVICE-PROTECTION limiter, not a billing meter: the
// allowances are generous for real interactive + automation use and only bite on
// sustained abuse. The AI SPEND ceiling is a separate mechanism (MonthlyAIBudgetUSD)
// — this bounds request volume, that bounds LLM cost.
//
// FAIL-OPEN by construction: a nil *Limiter allows everything, and a non-positive
// per-minute allowance means "unlimited". A rate limiter that locks customers out on
// a bug is worse than none, so every uncertain path allows the request.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// idleTTL is how long an unused per-key bucket is kept before it can be swept. A
// tenant that goes quiet for this long releases its limiter; the next request
// simply builds a fresh (full) bucket, which is fine — the point is to bound memory
// under many tenants, not to remember quiet tenants forever.
const idleTTL = 15 * time.Minute

// sweepEvery bounds how often a sweep runs (checked lazily on Allow), so a busy
// process does not walk the whole map on every request.
const sweepEvery = time.Minute

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
	perM int // the per-minute allowance this bucket was built for (rebuild on change)
}

// Limiter is a thread-safe, per-key token-bucket rate limiter. Keys are tenant ids.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time // injectable for tests
}

// New returns an empty limiter. Safe for concurrent use. No background goroutine is
// started (GC is lazy), so a Limiter never leaks.
func New() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: time.Now}
}

// Allow reports whether a request for key is permitted under a perMinute allowance.
//
//   - A nil limiter allows everything (feature disabled / not wired).
//   - perMinute <= 0 means unlimited (e.g. an Enterprise/unmetered plan).
//   - Otherwise it consumes one token from key's bucket, refilling at
//     perMinute/60 per second with a burst of a full minute's allowance (so a
//     legitimate burst — a dashboard firing many parallel reads — passes, and only
//     SUSTAINED excess is throttled).
func (l *Limiter) Allow(key string, perMinute int) bool {
	if l == nil || perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybeSweep(now)

	b := l.buckets[key]
	if b == nil || b.perM != perMinute {
		// Build (or rebuild on a plan change) a bucket: rate perMinute/60 per second,
		// burst = one full minute's allowance (at least 1).
		burst := perMinute
		if burst < 1 {
			burst = 1
		}
		b = &bucket{lim: rate.NewLimiter(rate.Limit(float64(perMinute)/60.0), burst), perM: perMinute}
		l.buckets[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}

// maybeSweep drops idle buckets, at most once per sweepEvery. Caller holds the lock.
func (l *Limiter) maybeSweep(now time.Time) {
	if now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > idleTTL {
			delete(l.buckets, k)
		}
	}
}
