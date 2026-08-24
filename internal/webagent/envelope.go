package webagent

import "sync"

// Envelope is an ENGAGEMENT-level request budget shared by every worker in a fleet run
// (ADR 0030 Phase C / D5 vector 2). Each worker's own Requester keeps its per-worker cap; the
// envelope is the absolute outer wall drawn down atomically across all of them — when it hits
// zero, no further probe fires anywhere, regardless of what any worker's local budget allows.
// This is what makes exploration bounded by construction rather than by cooperation: N workers
// can never spend more than the engagement authorized, even under concurrency.
//
// Nil-safe everywhere: a nil *Envelope means "no shared envelope" — exactly today's serial
// behavior (the strangler rule). The zero value is not usable; build with NewEnvelope.
type Envelope struct {
	mu   sync.Mutex
	left int
}

// NewEnvelope builds an envelope authorizing n requests for the whole engagement.
func NewEnvelope(n int) *Envelope {
	if n < 0 {
		n = 0
	}
	return &Envelope{left: n}
}

// Take atomically consumes one authorization. False means the engagement budget is spent —
// the caller must refuse the request (and say WHY: exhaustion, not silence).
func (e *Envelope) Take() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.left <= 0 {
		return false
	}
	e.left--
	return true
}

// Left reports the remaining engagement-wide authorizations.
func (e *Envelope) Left() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.left
}
