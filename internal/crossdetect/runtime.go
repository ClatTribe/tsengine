package crossdetect

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// runtime.go is the Runtime Protection correlation (ADR-0007 Phase 0). It joins
// in-app-firewall / RASP attack events to unified issues by endpoint, so a finding
// on a route that is ALSO being attacked in production is flagged
// observed-in-the-wild — the strongest exploitability signal there is.
//
// Orchestration glue only: it adds NO detection (the scanner found the weakness, the
// sensor observed the attack); it correlates two real signals on a concrete shared
// key (the endpoint path), never a guessed link (§10/§13).

// AnnotateRuntime marks each issue that shares an endpoint with ≥1 runtime attack
// event, setting Attacked + AttackCount. Issues without an endpoint (e.g. dependency
// CVEs) never match — a route attack isn't evidence about a package. Returns the
// annotated issues (in place) and the number that were flagged.
func AnnotateRuntime(issues []Issue, events []platform.RuntimeEvent) int {
	if len(events) == 0 {
		return 0
	}
	// Bucket attack counts by endpoint path.
	byPath := map[string]int{}
	for _, e := range events {
		if p := httpPath(e.Endpoint); p != "" {
			byPath[p]++
		}
	}
	flagged := 0
	for i := range issues {
		p := httpPath(issues[i].Endpoint)
		if p == "" {
			continue
		}
		if n := byPath[p]; n > 0 {
			issues[i].Attacked = true
			issues[i].AttackCount = n
			flagged++
		}
	}
	return flagged
}

// AnnotateCompensatingControls marks each issue whose endpoint had our OWN exploitation probe BLOCKED
// by a security control (a WAF/RASP event with Blocked:true carrying one of our probe canaries). That
// is grounded evidence of a compensating control: we tried the exploit through the customer's own
// perimeter and it was stopped, so an external attacker using the same technique is stopped by that
// rule today.
//
// It is DELIBERATELY the mirror of WithoutOwnProbes: that filter removes our own probes so they cannot
// read as a production ATTACK; this consumer WANTS them, because a control blocking OUR probe is the
// signal. So this must run on the RAW event stream (with own markers intact), not the filtered one.
//
// The refusal that keeps it honest (ADR 0027's rung-skipping warning, §10): it NEVER lowers Severity
// and NEVER marks the issue fixed. A WAF rule is not a code fix — it can be changed, bypassed, or fail
// to cover a variant — so this is breathing room for triage, stated as such, not closure. Returns the
// number of issues annotated.
func AnnotateCompensatingControls(issues []Issue, events []platform.RuntimeEvent, ownMarkers map[string]bool) int {
	if len(events) == 0 || len(ownMarkers) == 0 {
		return 0
	}
	// Endpoint paths where our OWN probe was blocked by a control.
	blockedOwn := map[string]bool{}
	for _, e := range events {
		if !e.Blocked || e.Marker == "" || !ownMarkers[e.Marker] {
			continue // must be OUR probe (marker is ours) AND actually blocked
		}
		if p := httpPath(e.Endpoint); p != "" {
			blockedOwn[p] = true
		}
	}
	n := 0
	for i := range issues {
		p := httpPath(issues[i].Endpoint)
		if p == "" || !blockedOwn[p] {
			continue
		}
		issues[i].WAFShielded = true
		issues[i].WAFShieldReason = "A security control (WAF/RASP) blocked this exact attack during " +
			"testing, so an attacker using the same technique is stopped by that rule today. This is " +
			"NOT a fix: the underlying code is still vulnerable, and a rule change, a bypass, or an " +
			"untested variant removes the mitigation. Prioritise the code fix; treat the block as " +
			"breathing room, not closure."
		n++
	}
	return n
}

// WithoutOwnProbes drops runtime events that are our OWN exposure-validation traffic — an event
// whose Marker is one of the tenant's probe canaries. A real-world attacker does not carry our
// canary, so a marker match is definitionally us. This matters because control-plane WAF logs
// (internal/controltest) land in the SAME RuntimeEvent stream these functions read: without this
// filter, our own pentest SQLi reflected in the customer's WAF log would be counted as an
// in-the-wild attack and open a severity-floor-bypassing incident (ADR-0007 Phase 0b) — the product
// reporting its own probe as someone attacking the customer. Events with no marker, or a marker that
// is not ours, are kept unchanged (a genuine attack carries no canary of ours).
func WithoutOwnProbes(events []platform.RuntimeEvent, ownMarkers map[string]bool) []platform.RuntimeEvent {
	if len(ownMarkers) == 0 || len(events) == 0 {
		return events
	}
	out := make([]platform.RuntimeEvent, 0, len(events))
	for _, e := range events {
		if e.Marker != "" && ownMarkers[e.Marker] {
			continue // our own probe, not a production attack
		}
		out = append(out, e)
	}
	return out
}

// AttackedKeys returns the set of finding identities (rule_id|endpoint — the same key
// the incident detector uses) whose endpoint is being attacked in production per a
// runtime event. The platform escalates these into incidents regardless of the
// severity floor (ADR-0007 Phase 0b: a live exploit attempt is itself urgent).
func AttackedKeys(findings []types.Finding, events []platform.RuntimeEvent) map[string]bool {
	if len(events) == 0 {
		return nil
	}
	underAttack := map[string]bool{}
	for _, e := range events {
		if p := httpPath(e.Endpoint); p != "" {
			underAttack[p] = true
		}
	}
	out := map[string]bool{}
	for _, f := range findings {
		if p := httpPath(f.Endpoint); p != "" && underAttack[p] {
			out[f.RuleID+"|"+f.Endpoint] = true
		}
	}
	return out
}

// httpPath normalizes a URL or route to its host-less path ("/search"), lower-cased,
// without scheme / host / query / trailing slash. Returns "" when there is no path
// component (so non-HTTP endpoints — a package coordinate, a bare host — never match).
func httpPath(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	i := strings.Index(s, "/")
	if i < 0 {
		return "" // no path segment (a bare host, or a package coordinate)
	}
	s = strings.TrimRight(s[i:], "/")
	if s == "" {
		return "/"
	}
	return s
}
