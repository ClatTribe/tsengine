package envelope

import "sync"

// Package envelope is ADR 0032 D7: the ENGAGEMENT-level budget primitive, shared
// by every model-backed subsystem (fleet request walls now; token budgets next).
// Drawdown is atomic — N concurrent consumers can never exceed the grant,
// regardless of scheduling.

// Envelope is an atomic counter of remaining authorizations.
type Envelope struct {
	mu   sync.Mutex
	left int
}

// New builds an envelope authorizing n units.
func New(n int) *Envelope {
	if n < 0 {
		n = 0
	}
	return &Envelope{left: n}
}

// Take atomically consumes one authorization. False means exhausted.
func (e *Envelope) Take() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.left <= 0 {
		return false
	}
	e.left--
	return true
}

// Left reports remaining authorizations.
func (e *Envelope) Left() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.left
}

// TokenBudget is an engagement-wide TOKEN budget for model-backed subsystems
// (sweep questions, disprover passes). Consumed post-hoc from brain usage
// deltas; a subsystem that exceeds it flips to breach-once semantics and the
// caller halts WITH disclosure rather than continuing silently.
type TokenBudget struct {
	mu    sync.Mutex
	left  int64
	spent int64
}

// NewTokenBudget authorizes n tokens for the engagement.
func NewTokenBudget(n int64) *TokenBudget {
	if n < 0 {
		n = 0
	}
	return &TokenBudget{left: n}
}

// Spend records u tokens against the budget. Returns whether the budget still
// has room AFTER this spend (first overrun consumes to zero and flips false once).
func (b *TokenBudget) Spend(u int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spent += u
	return b.spent <= b.left
}

// Spent returns total tokens consumed so far.
func (b *TokenBudget) Spent() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spent
}

// Left reports unspent tokens (never negative).
func (b *TokenBudget) Left() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.left - b.spent
	if l < 0 {
		l = 0
	}
	return l
}
