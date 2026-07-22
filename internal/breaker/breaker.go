// Package breaker is the auto-halt circuit-breaker for agentic offense. The guards (netguard egress,
// execpolicy capability envelope) refuse each out-of-scope action individually; a breaker watches the
// STREAM of those refusals and HALTS the agent when it sees a pattern that means "something is wrong"
// — repeated blocked-egress attempts, scope denials, a volume spike, a honeytoken touched.
//
// This is the piece that would have mattered in the OpenAI×Hugging Face incident: the model went
// "hyperfocused" and nothing tripped. A global kill-switch is necessary but too coarse and too late —
// it needs a human. A breaker trips automatically, in-flight, on the FIRST signs of a runaway.
//
// It LATCHES: once tripped it stays tripped until an explicit Reset (a human resume), and it retains
// the event trail — so an auto-halt is never silently undone, and a human always sees why.
package breaker

import (
	"fmt"
	"sync"
	"time"
)

// Kind is a containment signal a breaker counts. Each is something a guard already detects; the
// breaker only decides when a RATE of them means halt.
type Kind string

const (
	EgressBlocked Kind = "egress_blocked" // a request to a forbidden address (metadata/rebind) was refused
	ScopeDenied   Kind = "scope_denied"   // an out-of-scope tool/target was refused by the capability envelope
	VolumeAnomaly Kind = "volume_anomaly" // request rate crossed the expected envelope
	HoneytokenHit Kind = "honeytoken_hit" // a planted decoy credential/resource was touched (a strong compromise signal)
)

// Breaker trips when the count of a given Kind within the sliding window reaches its limit. A limit of
// 0 (or a Kind absent from limits) means that signal never trips the breaker on its own.
type Breaker struct {
	mu      sync.Mutex
	limits  map[Kind]int
	window  time.Duration
	now     func() time.Time
	events  []stamped
	tripped bool
	reason  string
}

type stamped struct {
	kind Kind
	at   time.Time
}

// New builds a breaker. window ≤ 0 means the whole session (no pruning). now defaults to time.Now.
func New(limits map[Kind]int, window time.Duration) *Breaker {
	l := make(map[Kind]int, len(limits))
	for k, v := range limits {
		l[k] = v
	}
	return &Breaker{limits: l, window: window, now: time.Now}
}

// WithClock injects a deterministic clock (tests). Returns b for chaining.
func (b *Breaker) WithClock(now func() time.Time) *Breaker { b.now = now; return b }

// Record registers one containment signal and reports whether the breaker is NOW tripped (either this
// event tripped it, or it was already latched). A honeytoken hit trips IMMEDIATELY regardless of limit
// — touching a decoy is never legitimate.
func (b *Breaker) Record(k Kind) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.events = append(b.events, stamped{kind: k, at: now})
	b.prune(now)
	if b.tripped {
		return true
	}
	if k == HoneytokenHit {
		b.trip("honeytoken touched — an unambiguous compromise signal")
		return true
	}
	if limit := b.limits[k]; limit > 0 && b.count(k, now) >= limit {
		b.trip(fmt.Sprintf("%s reached %d within %s — auto-halted", k, limit, b.windowLabel()))
		return true
	}
	return false
}

// Tripped reports whether the breaker has halted, and why.
func (b *Breaker) Tripped() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tripped, b.reason
}

// Reset clears the trip — the explicit human resume. The event trail is kept for the audit record.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tripped = false
	b.reason = ""
}

// Counts returns the current per-Kind count within the window (for telemetry / the UI).
func (b *Breaker) Counts() map[Kind]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.prune(now)
	out := map[Kind]int{}
	for _, e := range b.events {
		out[e.kind]++
	}
	return out
}

func (b *Breaker) trip(reason string) {
	b.tripped = true
	b.reason = reason
}

func (b *Breaker) prune(now time.Time) {
	if b.window <= 0 {
		return
	}
	cut := now.Add(-b.window)
	i := 0
	for _, e := range b.events {
		if e.at.After(cut) {
			b.events[i] = e
			i++
		}
	}
	b.events = b.events[:i]
}

func (b *Breaker) count(k Kind, now time.Time) int {
	n := 0
	for _, e := range b.events {
		if e.kind == k {
			n++
		}
	}
	return n
}

func (b *Breaker) windowLabel() string {
	if b.window <= 0 {
		return "the session"
	}
	return b.window.String()
}
