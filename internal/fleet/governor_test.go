package fleet

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGovernor_EnvelopeIsAbsolute is the load-bearing safety invariant (ADR 0030 D5 vector 2): under
// many concurrent workers each racing to reserve, the TOTAL granted never exceeds the envelope. This
// is the one place a concurrency bug would silently over-spend, so it is race-tested (go test -race).
func TestGovernor_EnvelopeIsAbsolute(t *testing.T) {
	const envelope = 1000
	g := NewGovernor(EnvelopeConfig{MaxRequests: envelope, Window: time.Minute})

	var wg sync.WaitGroup
	var totalGranted int64
	for w := 0; w < 32; w++ { // 32 workers hammering the pool
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				atomic.AddInt64(&totalGranted, int64(g.Reserve(1)))
			}
		}()
	}
	wg.Wait()

	if totalGranted != envelope {
		t.Errorf("32 workers × 200 reserves of an envelope of %d: total granted = %d, want exactly %d",
			envelope, totalGranted, envelope)
	}
	if g.Granted() != envelope || g.Remaining() != 0 {
		t.Errorf("governor accounting off: granted=%d remaining=%d", g.Granted(), g.Remaining())
	}
	// Exhausted → further reserves grant nothing.
	if g.Reserve(1) != 0 {
		t.Error("an exhausted envelope must grant 0")
	}
}

func TestGovernor_ReserveClampsToRemaining(t *testing.T) {
	g := NewGovernor(EnvelopeConfig{MaxRequests: 10})
	if got := g.Reserve(7); got != 7 {
		t.Fatalf("first reserve: got %d want 7", got)
	}
	if got := g.Reserve(7); got != 3 { // only 3 left → clamp
		t.Fatalf("clamped reserve: got %d want 3", got)
	}
	if got := g.Reserve(7); got != 0 {
		t.Fatalf("empty reserve: got %d want 0", got)
	}
}

// The shared latching breaker halts ALL reservations once tripped — the fleet-wide kill from a health
// signal (a WAF wall, a dead session).
func TestGovernor_BreakerHaltsReservations(t *testing.T) {
	g := NewGovernor(EnvelopeConfig{MaxRequests: 100})
	// SessionInvalid trips at 3 within the window.
	g.Record(SessionInvalid)
	g.Record(SessionInvalid)
	if g.Reserve(1) == 0 {
		t.Fatal("below the breaker threshold, reservations should still succeed")
	}
	g.Record(SessionInvalid) // third → trip
	if tripped, _ := g.Tripped(); !tripped {
		t.Fatal("three session-invalid signals must trip the shared breaker")
	}
	if g.Reserve(1) != 0 {
		t.Error("a tripped breaker must halt every worker's reservation, even with envelope left")
	}
}
