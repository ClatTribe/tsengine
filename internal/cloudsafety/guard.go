// Package cloudsafety is the structural safety harness for the AI Cloud Security
// Engineer (ADR 0002). Safety is enforced *outside* the model, not learned: even
// a reward-hacked or mis-prompted agent cannot mutate or exfiltrate, because the
// Guard physically rejects any action that is not read-only and caps live
// contact by a budget. Every call is logged (the audit trail = the evidence
// bundle's safety half).
package cloudsafety

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrMutating is returned when a non-read-only action is attempted.
var ErrMutating = errors.New("cloudsafety: action is not read-only")

// ErrBudget is returned when the live-call budget is exhausted.
var ErrBudget = errors.New("cloudsafety: live-call budget exhausted")

// readOnlyPrefixes are the AWS API verb prefixes that only observe state. The
// engineer is read-only by construction (ADR 0002): only these may run, no
// matter what the assumed IAM role allows.
var readOnlyPrefixes = []string{
	"Get", "List", "Describe", "Lookup", "Search", "BatchGet",
	"Simulate", // iam:SimulatePrincipalPolicy — effective-perms check
	"Generate", // accessanalyzer:Generate* (findings), no mutation
	"Head",     // s3:HeadObject — metadata only
}

// denyEvenIfReadOnlyLooking are actions whose verb looks read-only but that
// read sensitive *data contents* (never permitted — metadata only, ADR 0002) or
// otherwise breach the envelope. Explicit denylist beats the prefix allow.
var denyEvenIfReadOnlyLooking = map[string]bool{
	"s3:GetObject":                  true, // object CONTENTS — data, not metadata
	"secretsmanager:GetSecretValue": true,
	"ssm:GetParameter":              true, // may return a SecureString value
	"ssm:GetParameters":             true,
	"dynamodb:GetItem":              true, // row data
	"dynamodb:BatchGetItem":         true,
	"kms:Decrypt":                   true,
}

// ReadOnly reports whether an AWS API action ("service:Action") is safe for the
// engineer to call: a read-only verb AND not on the data-contents denylist.
func ReadOnly(action string) bool {
	if denyEvenIfReadOnlyLooking[action] {
		return false
	}
	verb := action
	if i := strings.IndexByte(action, ':'); i >= 0 {
		verb = action[i+1:]
	}
	for _, p := range readOnlyPrefixes {
		if strings.HasPrefix(verb, p) {
			return true
		}
	}
	return false
}

// Call is one logged live action (the audit trail).
type Call struct {
	Action     string    `json:"action"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason,omitempty"`
	Hypothesis string    `json:"hypothesis,omitempty"`
	At         time.Time `json:"at"`
}

// Guard enforces read-only + a live-call budget and records every attempt. It
// is the single chokepoint every live action passes through (the `validate`
// tool routes here). Safe for concurrent use.
type Guard struct {
	mu     sync.Mutex
	budget int
	used   int
	log    []Call
}

// NewGuard returns a Guard with the given live-call budget (≤0 = no live calls).
func NewGuard(budget int) *Guard { return &Guard{budget: budget} }

// Allow checks one live action for `hypothesis`. It returns nil only if the
// action is read-only AND budget remains; either way the attempt is logged.
// A denied action does NOT consume budget (we never executed it).
func (g *Guard) Allow(action, hypothesis string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	rec := Call{Action: action, Hypothesis: hypothesis, At: time.Now().UTC()}
	if !ReadOnly(action) {
		rec.Reason = "not read-only"
		g.log = append(g.log, rec)
		return fmt.Errorf("%w: %s", ErrMutating, action)
	}
	if g.used >= g.budget {
		rec.Reason = "budget exhausted"
		g.log = append(g.log, rec)
		return fmt.Errorf("%w (%d used / %d)", ErrBudget, g.used, g.budget)
	}
	g.used++
	rec.Allowed = true
	g.log = append(g.log, rec)
	return nil
}

// Used returns the number of live calls consumed.
func (g *Guard) Used() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.used
}

// Log returns a copy of the audit trail.
func (g *Guard) Log() []Call {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Call(nil), g.log...)
}
