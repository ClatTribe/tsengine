// Package autonomy decides when a kind of fix has EARNED the right to skip the approval desk.
//
// THE GAP. Every tier-2 action waited at the desk forever, however many times the same kind of fix had
// closed the same kind of finding. "Agents prepare, humans approve" only becomes less work for the human
// if approval can be withdrawn where the record has made it a formality — and only there.
//
// The record is the tenant's OWN (fieldevidence F2: which remediation closed which class), so the
// question asked is narrow and checkable: has THIS fix type closed THIS class every time it was tried
// here, with nothing left unconfirmed? Four rules keep it from becoming a way to stop looking:
//
//  1. OFFERED, NEVER TAKEN. A qualifying pair is offered to the owner; nothing applies on its own until
//     a named owner grants it. The grant records who, when, and how many closures it rested on.
//  2. TIER 2 ONLY. An irreversible (T3) action needs a named human signature by invariant; no record,
//     however long, earns that away. The kill-switch still wins over every grant.
//  3. ALL OR NOTHING per action. An action touching several classes applies on its own only when every
//     one of them is granted for its fix type.
//  4. ONE FAILURE ENDS IT. A grant is void the first time anything applied under it is recorded as not
//     closed, or as closed on evidence we could not confirm. That is read from the APPEND-ONLY
//     verification history, so a later clean scan cannot quietly restore it. Re-granting is the owner's
//     decision, and is refused until the record qualifies again.
package autonomy

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/fieldevidence"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// DefaultMinClosed is how many proven closures, with no failure and nothing unconfirmed, a pair needs
// before it is offered. Five is deliberately more than fieldevidence's floor for SHOWING a rate: being
// shown "closed 3 of 3" informs a human decision, while being granted removes the human.
const DefaultMinClosed = 5

// Options tunes the bar. Zero values take the defaults.
type Options struct {
	MinClosed int
}

func (o Options) minClosed() int {
	if o.MinClosed <= 0 {
		return DefaultMinClosed
	}
	return o.MinClosed
}

// Offer is a pair whose record qualifies and that nobody has granted yet.
type Offer struct {
	Class           string `json:"class"`
	RemediationType string `json:"remediation_type"`
	Closed          int    `json:"closed"`
}

// GrantStatus is a grant and whether it is working right now — and if not, why.
type GrantStatus struct {
	platform.AutonomyGrant
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
	// AppliedSince is how many actions of this pair have been applied since the grant, by anyone.
	AppliedSince int `json:"applied_since"`
}

// Report is what the owner is shown.
type Report struct {
	MinClosed int           `json:"min_closed"`
	Offers    []Offer       `json:"offers"`
	Grants    []GrantStatus `json:"grants"`
}

type pair struct{ class, rtype string }

func record(tenantID string, actions []platform.Action) map[pair]fieldevidence.RemediationEfficacy {
	c := fieldevidence.RemediationsForTenant(tenantID, actions, fieldevidence.Options{})
	out := map[pair]fieldevidence.RemediationEfficacy{}
	for _, e := range c.Entries {
		out[pair{e.Class, e.Type}] = e
	}
	return out
}

// qualifies says whether a pair's record earns an offer, and if not, the reason in words.
func qualifies(e fieldevidence.RemediationEfficacy, min int) (bool, string) {
	switch {
	case e.NotClosed > 0:
		return false, fmt.Sprintf("this fix failed to close the finding %d time(s)", e.NotClosed)
	case e.Unproven > 0:
		return false, fmt.Sprintf("%d application(s) could not be confirmed by a re-test", e.Unproven)
	case e.Closed < min:
		return false, fmt.Sprintf("%d proven closure(s) so far; %d are needed", e.Closed, min)
	}
	return true, ""
}

// Qualifies is the check the grant endpoint runs before accepting a grant.
func Qualifies(tenantID string, actions []platform.Action, class, rtype string, opts Options) (int, bool, string) {
	e, ok := record(tenantID, actions)[pair{class, rtype}]
	if !ok {
		return 0, false, "this fix has never been applied and re-tested for this kind of finding"
	}
	q, why := qualifies(e, opts.minClosed())
	return e.Closed, q, why
}

// failed reports whether a verification status means the fix did not demonstrably close the finding.
func failed(status string) bool {
	return status == platform.FixStatusStillPresent || status == platform.FixStatusRescanUnconfirmed
}

func classesOf(a platform.Action) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range a.FindingKeys {
		c := strings.TrimSpace(fieldevidence.ClassOf(k))
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func rtypeOf(a platform.Action) string {
	if a.Payload == nil {
		return ""
	}
	s, _ := a.Payload["remediation_type"].(string)
	return strings.TrimSpace(s)
}

// status evaluates one grant against everything applied since it was made, and against the record now.
func status(g platform.AutonomyGrant, rec map[pair]fieldevidence.RemediationEfficacy, actions []platform.Action, min int) GrantStatus {
	gs := GrantStatus{AutonomyGrant: g, Active: true}
	for _, a := range actions {
		if a.Status != platform.ActApplied || a.DecidedAt.Before(g.GrantedAt) || rtypeOf(a) != g.RemediationType {
			continue
		}
		match := false
		for _, c := range classesOf(a) {
			if c == g.Class {
				match = true
			}
		}
		if !match {
			continue
		}
		gs.AppliedSince++
		hist := a.VerificationHistory
		if len(hist) == 0 && a.Verification != nil {
			hist = []platform.FixVerification{*a.Verification}
		}
		for _, v := range hist {
			if failed(v.Status) && gs.Active {
				gs.Active = false
				gs.Reason = fmt.Sprintf("Action %s, applied on %s after this was allowed, was re-tested as %q. "+
					"Every action of this kind now goes back to the approval desk until you allow it again.",
					a.ID, a.DecidedAt.Format("2006-01-02"), v.Status)
			}
		}
	}
	if gs.Active {
		// The record can also go bad through an action applied BEFORE the grant — a re-attack that later
		// contradicted a fix the grant counted. The grant rested on that closure; it no longer holds.
		if q, why := qualifies(rec[pair{g.Class, g.RemediationType}], min); !q {
			gs.Active, gs.Reason = false, "The record it was allowed on no longer holds: "+why+"."
		}
	}
	return gs
}

// Evaluate builds the owner's view: what qualifies and is not yet allowed, and every grant's state.
func Evaluate(tenantID string, actions []platform.Action, grants []platform.AutonomyGrant, opts Options) Report {
	min := opts.minClosed()
	rec := record(tenantID, actions)
	r := Report{MinClosed: min, Offers: []Offer{}, Grants: []GrantStatus{}}
	granted := map[pair]bool{}
	for _, g := range grants {
		granted[pair{g.Class, g.RemediationType}] = true
		r.Grants = append(r.Grants, status(g, rec, actions, min))
	}
	for p, e := range rec {
		if granted[p] {
			continue
		}
		if q, _ := qualifies(e, min); q {
			r.Offers = append(r.Offers, Offer{Class: p.class, RemediationType: p.rtype, Closed: e.Closed})
		}
	}
	sort.Slice(r.Offers, func(i, j int) bool {
		if r.Offers[i].Closed != r.Offers[j].Closed {
			return r.Offers[i].Closed > r.Offers[j].Closed
		}
		return r.Offers[i].Class+r.Offers[i].RemediationType < r.Offers[j].Class+r.Offers[j].RemediationType
	})
	return r
}

// Authorize decides whether a freshly proposed action may skip the desk. ok=false is the default and
// covers every uncertainty: no type, no finding keys, a tier other than 2, any class without a working
// grant. The returned approver names the grant and the person who made it, for the action and the ledger.
func Authorize(tenantID string, a platform.Action, actions []platform.Action, grants []platform.AutonomyGrant, opts Options) (string, bool) {
	if a.Tier != platform.GateTier || len(grants) == 0 {
		return "", false
	}
	rtype, classes := rtypeOf(a), classesOf(a)
	if rtype == "" || len(classes) == 0 {
		return "", false
	}
	min := opts.minClosed()
	rec := record(tenantID, actions)
	var by []string
	for _, c := range classes {
		var found *platform.AutonomyGrant
		for i := range grants {
			if grants[i].Class == c && grants[i].RemediationType == rtype {
				found = &grants[i]
			}
		}
		if found == nil || !status(*found, rec, actions, min).Active {
			return "", false
		}
		by = append(by, fmt.Sprintf("%s (allowed by %s on %s)", c, found.GrantedBy, found.GrantedAt.Format("2006-01-02")))
	}
	return "earned autonomy: " + rtype + " for " + strings.Join(by, ", "), true
}

// OptionsFromEnv reads the operator's bar (TSENGINE_AUTONOMY_MIN_CLOSED). The desk hook and the API read
// the same function so the bar a grant was checked against is the bar it is applied with.
func OptionsFromEnv() Options {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TSENGINE_AUTONOMY_MIN_CLOSED")))
	if err != nil || n <= 0 {
		return Options{}
	}
	return Options{MinClosed: n}
}

// DeskHook adapts Authorize to hitl.Desk.Autonomy over the store. Any read failure keeps the action at
// the desk: skipping a human on data we could not read is the wrong direction to fail.
func DeskHook(st store.Store, opts Options) func(ctx context.Context, a platform.Action) (string, bool) {
	return func(ctx context.Context, a platform.Action) (string, bool) {
		t, err := st.GetTenant(ctx, a.TenantID)
		if err != nil || len(t.AutonomyGrants) == 0 {
			return "", false
		}
		acts, err := st.ListActions(ctx, a.TenantID)
		if err != nil {
			return "", false
		}
		return Authorize(a.TenantID, a, acts, t.AutonomyGrants, opts)
	}
}
