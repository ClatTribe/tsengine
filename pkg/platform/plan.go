package platform

import "strings"

// Plan tiers. The product sells three, matching the pricing page's sharp positioning (in CUSTOMER terms —
// no internal layer jargon): the deterministic + ML-based scanning engine is the self-serve product; the
// two AI agents are the premium:
//
//   - Free       — a taste of the deterministic + ML-based scanning engine: OSS scanners only, NO LLM
//     spend (the marginal cost), a hard asset cap, core compliance only.
//   - Core       — the FULL deterministic + ML-based scanning engine (all frameworks, continuous monitoring,
//     HITL apply) with NO operator-funded AI. The self-serve vs managed SERVICE MODEL differentiates
//     how it's delivered, not the entitlements. (Plan key stays "growth" — no stored-value migration.)
//   - Enterprise — "talk to us": the two AI agents (AI Security Engineer + AI Pentester) on top of the
//     scanning engine, plus unlimited assets, MSP/managed, SSO. The ONLY operator-AI-funded tier.
//
// The economic invariant: a tenant whose plan is not AI-enabled must never consume the OPERATOR's LLM
// budget. With AI now ENTERPRISE-ONLY, both Free AND Core are non-AI. (A tenant who brings their
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
	Plan      string `json:"plan"`
	Label     string `json:"label"`
	MaxAssets int    `json:"max_assets"` // -1 = unlimited
	// AIAgents — may this tenant run the AI Security Engineer / AI Pentester AT ALL, on ANY model
	// (including its own key)? This is the PRODUCT gate and it mirrors the pricing page: the agents are
	// what you buy, so Free ("No AI agents — scanning only") is false and every paid plan is true.
	// Distinct from AIEnabled, which is only about WHOSE MODEL BUDGET pays.
	AIAgents bool `json:"ai_agents"`
	// AIEnabled — do WE fund the model? The economic gate: only Enterprise spends the operator's LLM
	// budget. Core is true for AIAgents but false here — it runs the agents on the tenant's own key.
	AIEnabled            bool `json:"ai_enabled"`
	AutonomousPentest    bool `json:"autonomous_pentest"`    // ModeDeep / XBOW-class open-ended exploitation
	AllFrameworks        bool `json:"all_frameworks"`        // all 22 vs core (SOC 2 + 1)
	ContinuousMonitoring bool `json:"continuous_monitoring"` // scheduled re-scan + incidents, vs on-demand
	HumanInLoopApply     bool `json:"human_in_loop_apply"`   // gated remediation apply loop
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
			AIAgents: true, AIEnabled: true, AutonomousPentest: true, AllFrameworks: true,
			ContinuousMonitoring: true, HumanInLoopApply: true,
		}
	case PlanGrowth:
		// The "Core" tier — what the pricing page sells: BOTH AI agents (AIAgents), run on the TENANT'S
		// OWN model key, plus every scanner, all frameworks, monitoring and the approval loop. AIEnabled
		// stays FALSE on purpose: that gates the OPERATOR's model budget, which is the Enterprise tier.
		// (Plan key stays "growth"; the customer-facing label is "Core".)
		return PlanLimits{
			Plan: PlanGrowth, Label: "Core", MaxAssets: 25,
			AIAgents: true, AIEnabled: false, AutonomousPentest: false, AllFrameworks: true,
			ContinuousMonitoring: true, HumanInLoopApply: true,
		}
	default:
		// Free is scanning only — exactly what the pricing page promises ("No AI agents"). AIAgents is
		// false, so the agents are refused even if the tenant configures its own key: the agents are the
		// product, and giving them away free would leave nothing to sell.
		return PlanLimits{
			Plan: PlanFree, Label: "Free", MaxAssets: 2,
			AIAgents: false, AIEnabled: false, AutonomousPentest: false, AllFrameworks: false,
			ContinuousMonitoring: false, HumanInLoopApply: false,
		}
	}
}
