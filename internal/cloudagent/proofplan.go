package cloudagent

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// proofplan.go turns "how much of this path did the provider confirm" from a RATIO into a plan with a
// per-hop verdict — ADR 0024 P1b.
//
// C2 established the every-hop rule and expressed it as `confirmedHops/authHops`. The rule is right
// and the ratio hid a defect of its own, which is the reason this file exists rather than a struct
// rename: THE OLD SHAPE COULD NOT REPRESENT A DENIAL.
//
// `hopConfirmed` looked only for an ALLOW, so a hop the provider explicitly REFUSED counted exactly
// like a hop nobody ever asked about — both merely "not confirmed". A path the provider had told us
// was CLOSED therefore rendered as "1/3 confirmed": partial evidence that it is OPEN, computed from
// authoritative evidence that it is not. That is C9's defect one layer out — denials computed and
// then flattened away at the consumer — and it is the more dangerous instance, because C9 lost the
// denial from a report while this one inverts its meaning.
//
// The plan also separates the two ways a hop can fail to be confirmed, which the ratio merged:
// UNTESTED (nobody asked — budget exhausted, or the agent never got there) and UNKNOWN (we asked and
// the provider could not answer — throttled, unsupported, no simulate permission). "We ran out of
// budget" and "the provider refused to say" are different facts about our coverage and a reader
// chasing a gap needs to know which one they have.

// HopStatus is the provider's answer about one authorization-requiring hop.
type HopStatus string

const (
	// HopConfirmed — the provider allowed at least one action across this hop.
	HopConfirmed HopStatus = "confirmed"
	// HopDenied — the provider was asked and refused every action we asked about. Authoritative
	// negative evidence: this hop is shut for the moves we tried.
	HopDenied HopStatus = "denied"
	// HopUnknown — we asked and the provider could not answer.
	HopUnknown HopStatus = "unknown"
	// HopUntested — nobody asked.
	HopUntested HopStatus = "untested"
)

// PathStatus is the whole path's authorization standing.
type PathStatus string

const (
	// PathConfirmed — every authorization-requiring hop is confirmed ALLOW.
	PathConfirmed PathStatus = "confirmed"
	// PathDenied — at least one required hop was authoritatively refused, so the path as traced does
	// not authorize. It does NOT mean the target is unreachable by some other route (ADR 0024 C3).
	PathDenied PathStatus = "denied"
	// PathPartial — some required hops confirmed, none denied, the rest unresolved.
	PathPartial PathStatus = "partial"
	// PathUnknown — nothing about this path's authorization was established either way.
	PathUnknown PathStatus = "unknown"
)

// RequiredCheck is one authorization decision a path depends on, and what the provider said.
type RequiredCheck struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Kind   string    `json:"kind"`
	Status HopStatus `json:"status"`
	// Detail is the provider's own words for a decided hop (which statement matched); Why explains an
	// unknown. Both empty for untested — there is nothing to explain about a question never asked.
	Detail string `json:"detail,omitempty"`
	Why    string `json:"why,omitempty"`
}

// AuthorizationProofPlan is what a path REQUIRES in order to authorize, and how much of that is
// established. It is built whether or not a prober is wired: the required set is a property of the
// GRAPH, so even with nothing probed it says what would have to be true — which is the difference
// between "we have no proof" and "there is nothing to prove".
type AuthorizationProofPlan struct {
	Status PathStatus      `json:"status"`
	Checks []RequiredCheck `json:"checks,omitempty"`
	// Confirmed/Required keep the C2 ratio for renderers that want the short form.
	Confirmed int `json:"confirmed"`
	Required  int `json:"required"`
}

// Coverage renders the C2 short form, unchanged, so existing consumers keep working.
func (p AuthorizationProofPlan) Coverage() string {
	return itoa(p.Confirmed) + "/" + itoa(p.Required)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// authorizationProofPlan builds the plan for a recorded path.
func (cc *Context) authorizationProofPlan(path []string) AuthorizationProofPlan {
	var plan AuthorizationProofPlan
	if len(path) < 2 {
		plan.Status = PathUnknown
		return plan
	}
	for i := 0; i < len(path)-1; i++ {
		from, to := path[i], path[i+1]
		e, ok := edgeBetween(cc.Snap, from, to)
		if !ok || !edgeNeedsAuthorization(e.Kind) {
			// A network_reach edge is a reachability FACT, not an IAM decision — the next rung up
			// (C3). Excluded from the denominator rather than counted as authorized, so it can
			// neither block nor manufacture a confirmation.
			continue
		}
		chk := RequiredCheck{From: from, To: to, Kind: string(e.Kind)}
		chk.Status, chk.Detail, chk.Why = cc.hopStatus(from, to)
		plan.Checks = append(plan.Checks, chk)
		plan.Required++
		if chk.Status == HopConfirmed {
			plan.Confirmed++
		}
	}
	plan.Status = rollUp(plan.Checks)
	return plan
}

// rollUp decides the path's standing from its hops.
//
// A DENIAL DOMINATES. One authoritatively refused hop means the path as traced does not authorize,
// and reporting that as "partial" would present authoritative negative evidence as partial progress
// toward a positive claim. Confirmation requires every hop, per C2 — so the two strong verdicts are
// asymmetric by design: ALL for a confirmation, ANY for a refusal, because a chain is as strong as
// its weakest link and as broken as its most broken one.
func rollUp(checks []RequiredCheck) PathStatus {
	if len(checks) == 0 {
		return PathUnknown
	}
	confirmed := 0
	for _, c := range checks {
		if c.Status == HopDenied {
			return PathDenied
		}
		if c.Status == HopConfirmed {
			confirmed++
		}
	}
	switch {
	case confirmed == len(checks):
		return PathConfirmed
	case confirmed > 0:
		return PathPartial
	default:
		return PathUnknown
	}
}

// hopStatus reads every probe taken across this hop and reduces them to one answer.
//
// ALLOW WINS OVER DENY AT THE HOP LEVEL, which is the opposite of the path-level rule and is correct
// for the opposite reason: a hop is a disjunction (any permitted action traverses it) while a path is
// a conjunction (every hop must hold). So a hop where iam:PassRole was denied but sts:AssumeRole was
// allowed is traversable, and calling it denied would refute a path an attacker can walk.
func (cc *Context) hopStatus(from, to string) (HopStatus, string, string) {
	var (
		denyDetail string
		unknownWhy string
		sawDeny    bool
		sawUnknown bool
	)
	for k, r := range cc.probes {
		parts := strings.SplitN(k, "\x00", 3)
		if len(parts) != 3 || parts[0] != from || parts[2] != to {
			continue
		}
		switch r.Verdict {
		case VerdictAllow:
			return HopConfirmed, r.Detail, ""
		case VerdictDeny:
			sawDeny = true
			if denyDetail == "" {
				denyDetail = r.Detail
			}
		default:
			sawUnknown = true
			if unknownWhy == "" {
				unknownWhy = r.Why
			}
		}
	}
	switch {
	case sawDeny:
		return HopDenied, denyDetail, ""
	case sawUnknown:
		return HopUnknown, "", unknownWhy
	default:
		// Nobody asked. Distinct from unknown: "we ran out of budget" and "the provider refused to
		// say" are different facts about our coverage, and a reader chasing a gap needs to know which.
		return HopUntested, "", ""
	}
}

var _ = cloudgraph.EdgeAssumeRole // the plan is defined over graph edge kinds
