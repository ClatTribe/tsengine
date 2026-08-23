package scubaingest

import "sort"

// Agreement states between CISA's tool and ours.
const (
	// AgreedFail: both found the policy violated. The strongest corroboration available for an
	// identity finding — the authority that publishes the baseline reached the same verdict.
	AgreedFail = "agreed_fail"
	// AgreedPass: both found it satisfied.
	AgreedPass = "agreed_pass"
	// WeMissed: CISA's tool failed the policy and we did not. A gap in OUR coverage, and the reason
	// this correlation is worth running at all.
	WeMissed = "we_missed"
	// TheyMissed: we flagged it and their run passed it. NOT a win by default — it is equally a
	// candidate false positive of ours, and the name says only what happened.
	TheyMissed = "they_missed"
	// Unjudged: their run errored, warned or omitted. Not agreement, and never counted as one.
	Unjudged = "unjudged"
)

// PolicyComparison is one policy, both verdicts.
type PolicyComparison struct {
	PolicyID    string   `json:"policy_id"`
	State       string   `json:"state"`
	Criticality string   `json:"criticality,omitempty"`
	TheirResult string   `json:"their_result"`
	OurRules    []string `json:"our_rules,omitempty"`
	Requirement string   `json:"requirement,omitempty"`
}

// Correlation is the estate-wide comparison.
type Correlation struct {
	Policies   []PolicyComparison `json:"policies"`
	AgreedFail int                `json:"agreed_fail"`
	AgreedPass int                `json:"agreed_pass"`
	WeMissed   int                `json:"we_missed"`
	TheyMissed int                `json:"they_missed"`
	Unjudged   int                `json:"unjudged"`
	// Unmapped counts policies their run judged that we have no rule mapping for at all. Distinct
	// from WeMissed: there we have a detector and it stayed quiet, here we never had one. Merged,
	// a coverage hole would read as a detection failure and send someone to debug the wrong thing.
	Unmapped int    `json:"unmapped"`
	Caveat   string `json:"caveat"`
}

const caveat = "Compared against a ScubaGear/ScubaGoggles run the customer performed themselves. " +
	"\"They missed\" is not a win by default — it is equally a candidate false positive of ours. " +
	"Policies their run errored, warned or omitted are counted as unjudged, never as agreement."

// Correlate compares CISA's verdicts with ours.
//
// policyRules maps a SCuBA policy id to the tsengine rule ids that detect its violation (the mapping
// the SCuBA bench already maintains and proves by execution). firedRules is the set of our rule ids
// that actually fired for this tenant. Both are passed in so this package stays a leaf — and so the
// mapping has exactly one home rather than a second copy that can drift from the proven one.
func Correlate(outcomes []Outcome, firedRules map[string]bool, policyRules map[string][]string) Correlation {
	c := Correlation{Caveat: caveat}
	for _, o := range outcomes {
		cmp := PolicyComparison{PolicyID: o.PolicyID, Criticality: o.Criticality,
			TheirResult: o.Result, Requirement: o.Requirement}

		if !o.Judged() {
			cmp.State = Unjudged
			c.Unjudged++
			c.Policies = append(c.Policies, cmp)
			continue
		}
		rules, mapped := policyRules[o.PolicyID]
		if !mapped || len(rules) == 0 {
			// We have no detector for this policy. Reported as its own thing: merged into WeMissed it
			// would read as a detector that stayed quiet, and send someone to debug a rule that does
			// not exist.
			cmp.State = Unjudged
			c.Unmapped++
			c.Policies = append(c.Policies, cmp)
			continue
		}
		cmp.OurRules = rules

		var weFlagged bool
		for _, r := range rules {
			// A "~"-prefixed rule is a PARTIAL mapping in the bench's vocabulary; it is a weaker
			// adjacent check, so it does not count as us having caught the policy.
			if len(r) > 0 && r[0] == '~' {
				continue
			}
			if firedRules[r] {
				weFlagged = true
				break
			}
		}
		switch {
		case o.Failed() && weFlagged:
			cmp.State, c.AgreedFail = AgreedFail, c.AgreedFail+1
		case o.Failed() && !weFlagged:
			cmp.State, c.WeMissed = WeMissed, c.WeMissed+1
		case !o.Failed() && weFlagged:
			cmp.State, c.TheyMissed = TheyMissed, c.TheyMissed+1
		default:
			cmp.State, c.AgreedPass = AgreedPass, c.AgreedPass+1
		}
		c.Policies = append(c.Policies, cmp)
	}
	sort.Slice(c.Policies, func(i, j int) bool { return c.Policies[i].PolicyID < c.Policies[j].PolicyID })
	return c
}
