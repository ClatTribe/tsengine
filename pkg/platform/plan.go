package platform

import "strings"

// Plan tiers. The product sells three, matching the pricing page:
//
//   - Free       — genuinely free to RUN for us: deterministic OSS scanners only, NO LLM
//     spend (the marginal cost), a hard asset cap, core compliance only.
//   - Growth     — the one paid tier: the AI security+compliance engineer turned on
//     (L2 agent, AI fixes, continuous monitoring), all frameworks, HITL apply.
//   - Enterprise — "talk to us": unlimited assets, autonomous pentest, MSP/managed, SSO.
//
// The economic invariant: a tenant whose plan is not AI-enabled must never consume the
// OPERATOR's LLM budget. (A tenant who brings their OWN key — §18.5 — may use AI on any
// plan, because that cost isn't ours; that exception lives in resolveAgentLLM, not here.)
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
// read from this one function, so the product and the billing story can never drift.
func Entitlements(plan string) PlanLimits {
	switch NormalizePlan(plan) {
	case PlanEnterprise:
		return PlanLimits{
			Plan: PlanEnterprise, Label: "Enterprise", MaxAssets: -1,
			AIEnabled: true, AutonomousPentest: true, AllFrameworks: true,
			ContinuousMonitoring: true, HumanInLoopApply: true,
		}
	case PlanGrowth:
		return PlanLimits{
			Plan: PlanGrowth, Label: "Growth", MaxAssets: 25,
			AIEnabled: true, AutonomousPentest: false, AllFrameworks: true,
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
