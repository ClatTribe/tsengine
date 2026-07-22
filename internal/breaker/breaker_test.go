package breaker

import (
	"testing"
	"time"
)

func clockAt(t *time.Time) func() time.Time { return func() time.Time { return *t } }

// TestBreaker_TripsAtThreshold: below the limit stays live; at the limit it halts, with a reason.
func TestBreaker_TripsAtThreshold(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	b := New(map[Kind]int{EgressBlocked: 3}, time.Minute).WithClock(clockAt(&now))
	if b.Record(EgressBlocked) || b.Record(EgressBlocked) {
		t.Fatal("must not trip below the threshold")
	}
	if !b.Record(EgressBlocked) {
		t.Fatal("the 3rd blocked-egress must trip the breaker")
	}
	tripped, reason := b.Tripped()
	if !tripped || reason == "" {
		t.Errorf("want tripped with a reason, got %v %q", tripped, reason)
	}
}

// TestBreaker_WindowPrunesOldEvents: signals outside the window don't accumulate, so an occasional
// benign denial over a long run never trips it.
func TestBreaker_WindowPrunesOldEvents(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	b := New(map[Kind]int{ScopeDenied: 2}, time.Minute).WithClock(clockAt(&now))
	b.Record(ScopeDenied)          // t=0
	now = now.Add(2 * time.Minute) // slide past the window
	if b.Record(ScopeDenied) {     // only 1 within the window now
		t.Fatal("a stale event must not count — must not trip")
	}
	if !b.Record(ScopeDenied) { // now 2 within the window
		t.Fatal("2 within the window must trip")
	}
}

// TestBreaker_Latches: once tripped it stays tripped (even for other kinds) until an explicit Reset —
// an auto-halt is never silently undone; only a human resumes.
func TestBreaker_Latches(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	b := New(map[Kind]int{EgressBlocked: 1}, 0).WithClock(clockAt(&now))
	b.Record(EgressBlocked)
	if tr, _ := b.Tripped(); !tr {
		t.Fatal("should be tripped")
	}
	if !b.Record(ScopeDenied) {
		t.Error("a latched breaker reports tripped for any subsequent signal")
	}
	b.Reset() // the human resume
	if tr, _ := b.Tripped(); tr {
		t.Error("Reset must clear the trip")
	}
}

// TestBreaker_HoneytokenTripsImmediately: touching a decoy is never legitimate — halt on the first hit
// regardless of any limit.
func TestBreaker_HoneytokenTripsImmediately(t *testing.T) {
	b := New(nil, time.Minute) // no limits configured
	if !b.Record(HoneytokenHit) {
		t.Fatal("a single honeytoken hit must trip immediately")
	}
	if _, reason := b.Tripped(); reason == "" {
		t.Error("want a reason naming the honeytoken")
	}
}

// TestBreaker_ZeroLimitNeverTrips: a signal with no configured limit doesn't trip on its own.
func TestBreaker_ZeroLimitNeverTrips(t *testing.T) {
	b := New(map[Kind]int{EgressBlocked: 2}, time.Minute)
	for i := 0; i < 50; i++ {
		if b.Record(VolumeAnomaly) { // VolumeAnomaly has no limit
			t.Fatal("an unlimited kind must never trip on its own")
		}
	}
}
