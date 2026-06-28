package platform

import "strings"

// Plan tiers. The product sells three, matching the pricing page's sharp positioning — the
// deterministic L1.7 substrate is the self-serve product; the two AI teammates are the premium:
//
//   - Free       — a taste of the deterministic L1.7 substrate: OSS scanners only, NO LLM
//     spend (the marginal cost), a hard asset cap, core compliance only.
//   - Substrate  — the FULL deterministic L1.7 substrate (all frameworks, continuous monitoring,
//     HITL apply) with NO operator-funded AI. The self-serve vs managed SERVICE MODEL differentiates
//     how it's delivered, not the entitlements. (Plan key stays "growth" — no stored-value migration.)
//   - Enterprise — "talk to us": the two AI teammates (AI Security Engineer + AI Pentester) on top of
//     the substrate, plus unlimited assets, MSP/managed, SSO. The ONLY operator-AI-funded tier.
//
// The economic invariant: a tenant whose plan is not AI-enabled must never consume the OPERATOR's LLM
// budget. With AI now ENTERPRISE-ONLY, both Free AND Substrate are non-AI. (A tenant who brings their
// OWN key — §18.5 — may use AI on any plan, because that cost isn't ours; that exception lives in
// resolveAgentLLM, not here.)
const (
	PlanFree       = "free"
	PlanGrowth     = "growth"
	PlanEnterprise = "enterprise"
)

// PlanLimits is the entitlement set for a plan — what a tenant on it may do. -1 means
// unlimited. AIEnabled is the load-bearing one: it gates the operator-funded L2/LLM work
// (cloud investigation, AI remediation, ModeDeep) so the Free tier costs us ~nothing.
type PlanLimits struct {
	Plan                 string `json:"plan"`
	Label                string `json:"label"`
	MaxAssets            int    `json:"max_assets"`            // -1 = unlimited
	AIEnabled            bool   `json:"ai_enabled"`            // operator-funded L2 agent / AI fixes / LLM
	AutonomousPentest    bool   `json:"autonomous_pentest"`    // ModeDeep / XBOW-class open-ended exploitation
	AllFrameworks        bool   `json:"all_frameworks"`        // all 22 vs core (SOC 2 + 1)
	ContinuousMonitoring bool   `json:"continuous_monitoring"` // scheduled re-scan + incidents, vs on-demand
	HumanInLoopApply     bool   `json:"human_in_loop_apply"`   // gated remediation apply loop
}

// NormalizePlan maps a raw plan string (case/space-insensitive, with legacy aliases) to a
// canonical tier. Unknown / empty → Free (fail-safe: an unrecognized plan never silently
// grants paid entitlements or our LLM budget).
func NormalizePlan(plan string) string {
	p := strings.ToLower(strings.TrimSpace(plan))
	switch {
	case p == PlanEnterprise || p == "scale" || p == "custom" || p == "unlimited":
		return PlanEnterprise
	case p == PlanGrowth || p == "starter" || p == "team" || p == "pro":
		return PlanGrowth
	default:
		return PlanFree
	}
}

// Entitlements returns the limits for a plan. The pricing page and every server-side gate
// read from this one function, so the product and the billing story can never drift. A plan
// string may carry "+"-joined ADD-ONS on top of its base tier (e.g. "growth+pentest") — today the
// only add-on is "pentest" (the autonomous-pentest add-on), which unlocks AutonomousPentest on any
// base tier. This is the ONE source of truth for the autonomous-pentest gate (no string-match drift).
func Entitlements(plan string) PlanLimits {
	p := strings.ToLower(strings.TrimSpace(plan))
	lim := baseEntitlements(strings.SplitN(p, "+", 2)[0]) // base tier = the part before the first add-on
	if strings.Contains(p, "pentest") {                   // the autonomous-pentest add-on (any plan carrying the token)
		lim.AutonomousPentest = true
	}
	return lim
}

// baseEntitlements returns the limits for a base tier (no add-ons).
func baseEntitlements(plan string) PlanLimits {
	switch NormalizePlan(plan) {
	case PlanEnterprise:
		return PlanLimits{
			Plan: PlanEnterprise, Label: "Enterprise", MaxAssets: -1,
			AIEnabled: true, AutonomousPentest: true, AllFrameworks: true,
			ContinuousMonitoring: true, HumanInLoopApply: true,
		}
	case PlanGrowth:
		// The "Substrate" tier: the full deterministic L1.7 substrate, but NO operator-funded AI —
		// the two AI teammates are Enterprise-only. (Plan key stays "growth"; the label/positioning is
		// "Substrate". A tenant on this tier can still use AI by bringing its own LLM key — §18.5.)
		return PlanLimits{
			Plan: PlanGrowth, Label: "Substrate", MaxAssets: 25,
			AIEnabled: false, AutonomousPentest: false, AllFrameworks: true,
			ContinuousMonitoring: true, HumanInLoopApply: true,
		}
	default:
		return PlanLimits{
			Plan: PlanFree, Label: "Free", MaxAssets: 2,
			AIEnabled: false, AutonomousPentest: false, AllFrameworks: false,
			ContinuousMonitoring: false, HumanInLoopApply: false,
		}
	}
}
