package platform

import (
	"fmt"
	"strings"
)

// Plan tiers. The product sells three, matching the pricing page's sharp positioning (in CUSTOMER terms —
// no internal layer jargon): the deterministic + ML-based scanning engine is the self-serve product; the
// two AI agents are the premium:
//
//   - Free       — a taste of the deterministic + ML-based scanning engine: OSS scanners only, NO LLM
//     spend (the marginal cost), a hard asset cap, core compliance only.
//   - Core       — the full deterministic engine PLUS the AI Security Engineer, self-serve. (Plan key
//     stays "growth" — no stored-value migration.)
//   - Core+pentest — Core plus the AI Pentester, via the existing "+pentest" add-on token. This is the
//     "Growth" tier on the pricing page; it needs no new plan key.
//   - Enterprise — "talk to us" for what genuinely needs a conversation: unlimited assets, MSP/managed
//     delivery, SSO. NOT a gate on the AI agents — those are self-serve above.
//   - Audit      — THE PER-APPLICATION SKU. Not a subscription: a fixed price per application, for the
//     buyer who purchases a Safe-to-Host certificate (Indian public-sector VAPT tenders, and the
//     CERT-In-empanelled firms that win them). Those tenders pay 100% on acceptance of the final
//     report and never in advance, so the unit of sale is an AuditOrder per application (types.go) and
//     the money is due only once the buyer ACCEPTS the certificate. The plan's asset cap is the number
//     of applications purchased (Tenant.AuditApplications) — read through EntitlementsFor, since a plan
//     string cannot carry a count. AI is on (the price covers it: the review needs the engine's
//     triage and the pentester's proof); continuous monitoring is off (an audit is a point-in-time
//     engagement with a re-test, not a heartbeat).
//
// The economic invariant is unchanged: a tenant whose plan is not AI-enabled must never consume the
// OPERATOR's LLM budget. Free is that tenant. What changed is only WHERE the line sits — a paying
// self-serve tier now funds the operator model, because the price covers it. (A tenant who brings their
// OWN key — §18.5 — may use AI on any plan, because that cost isn't ours; that exception lives in
// resolveAgentLLM, not here. And a customer may still choose to run less than they bought — AIMode.)
const (
	PlanFree       = "free"
	PlanGrowth     = "growth"
	PlanEnterprise = "enterprise"
	PlanAudit      = "audit"
)

// AuditListPriceINR is the list price of ONE application under the per-application SKU, in rupees,
// exclusive of GST. It is the default an AuditOrder is created at; an operator may set a different
// agreed price per order. Mirrored on the pricing page — change both.
//
// Where the number comes from: nine public-sector VAPT bids read in 2026-09 priced a web-application
// audit with re-test and certificate at roughly ₹40–60k per application at the small end. This sits in
// that band, because a buyer on GeM compares it against exactly those.
const AuditListPriceINR = 49999

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
	// APIRatePerMin is the fair-use ceiling on authenticated /v1 requests per minute
	// for a tenant on this plan — a SERVICE-PROTECTION limit (one tenant's runaway
	// automation can't degrade the shared platform), NOT a billing meter. Paid tiers
	// get more headroom; 0 = unmetered (Enterprise). It is deliberately generous:
	// interactive + normal automation stays well under it, and only sustained excess
	// is throttled (429 + Retry-After). AI *spend* is bounded separately by
	// MonthlyAIBudgetUSD.
	APIRatePerMin int `json:"api_rate_per_min"`
}

// NormalizePlan maps a raw plan string (case/space-insensitive, with legacy aliases) to a
// canonical tier. Unknown / empty → Free (fail-safe: an unrecognized plan never silently
// grants paid entitlements or our LLM budget).
func NormalizePlan(plan string) string {
	p := strings.ToLower(strings.TrimSpace(plan))
	switch {
	case p == PlanEnterprise || p == "scale" || p == "custom" || p == "unlimited":
		return PlanEnterprise
	// "core" is the name this tier carries on the pricing page and in PlanLimits.Label. It was not an
	// accepted alias, so the one word a customer or operator actually reads did not resolve.
	case p == PlanGrowth || p == "core" || p == "starter" || p == "team" || p == "pro":
		return PlanGrowth
	case p == PlanAudit || p == "per-application" || p == "per-app":
		return PlanAudit
	default:
		return PlanFree
	}
}

// EntitlementsFor is Entitlements read through the TENANT rather than the plan string alone. It
// exists for the one tier whose limit is a purchased COUNT: on the per-application SKU the asset cap
// is the number of applications bought, which a plan string cannot carry. Every other tier is
// unchanged. Callers that gate on a cap (asset creation, discovery) read this; a caller that only
// needs a capability flag may still read Entitlements.
//
// Zero applications purchased → zero targets allowed. A buyer who has ordered nothing has no
// application under audit, and a cap that defaulted to "some" would let an unpaid engagement scan.
func EntitlementsFor(t Tenant) PlanLimits {
	lim := Entitlements(t.Plan)
	if lim.Plan == PlanAudit {
		lim.MaxAssets = t.AuditApplications
		if lim.MaxAssets < 0 {
			lim.MaxAssets = 0
		}
	}
	return lim
}

// knownAddOns are the "+"-joined add-on tokens a plan string may carry.
var knownAddOns = map[string]bool{"pentest": true}

// ValidatePlan is the STRICT counterpart to NormalizePlan, for the one place where guessing is
// dangerous: an operator setting a paying customer's plan. NormalizePlan is deliberately
// fail-safe — anything unrecognized becomes Free — which is right for reading a stored value
// but catastrophic on write, where a typo ("groth") would silently DOWNGRADE a customer who
// just paid. ValidatePlan instead returns an error for anything it does not recognize.
//
// It accepts the same aliases and "+"-joined add-ons as Entitlements (e.g. "pro+pentest") and
// returns the canonical form to store.
func ValidatePlan(plan string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(plan))
	if p == "" {
		return "", fmt.Errorf("plan is empty")
	}
	parts := strings.Split(p, "+")
	base := strings.TrimSpace(parts[0])

	var canonical string
	switch base {
	case PlanEnterprise, "scale", "custom", "unlimited":
		canonical = PlanEnterprise
	case PlanGrowth, "core", "starter", "team", "pro":
		canonical = PlanGrowth
	case PlanAudit, "per-application", "per-app":
		canonical = PlanAudit
	case PlanFree, "":
		canonical = PlanFree
	default:
		return "", fmt.Errorf("unknown plan tier %q (want free, core, growth, audit, or enterprise)", base)
	}
	for _, add := range parts[1:] {
		add = strings.TrimSpace(add)
		if !knownAddOns[add] {
			return "", fmt.Errorf("unknown add-on %q (want pentest)", add)
		}
		canonical += "+" + add
	}
	return canonical, nil
}

// Entitlements returns the limits for a plan. The pricing page and every server-side gate
// read from this one function, so the product and the billing story can never drift. A plan
// string may carry "+"-joined ADD-ONS on top of its base tier (e.g. "growth+pentest") — today the
// only add-on is "pentest" (the autonomous-pentest add-on), which unlocks AutonomousPentest on any
// base tier. This is the ONE source of truth for the autonomous-pentest gate (no string-match drift).
func Entitlements(plan string) PlanLimits {
	p := strings.ToLower(strings.TrimSpace(plan))
	base := strings.SplitN(p, "+", 2)[0] // base tier = the part before the first add-on
	lim := baseEntitlements(base)

	// AN ADD-ON RIDES A REAL TIER OR IT DOES NOT RIDE AT ALL.
	//
	// This used to be a bare substring test, so "core+pentest" — a typo of our own public tier name —
	// returned Free's limits WITH AutonomousPentest set. The base fell through NormalizePlan to Free
	// (correctly fail-safe) while the add-on was granted anyway, which is the one combination that
	// should be impossible: an unrecognized plan handing out the most privileged capability we have.
	//
	// Checking the base here means Entitlements is safe on its own, rather than safe only because some
	// caller validated first. That matters because Entitlements IS the gate — autonomousPentestEntitled
	// reads AutonomousPentest with no other condition.
	if _, err := ValidatePlan(base); err != nil {
		return lim
	}
	if strings.Contains(p, "pentest") { // the autonomous-pentest add-on (any RECOGNIZED tier carrying the token)
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
			APIRatePerMin: 0, // unmetered
		}
	case PlanAudit:
		// The per-application SKU. MaxAssets is a PLACEHOLDER here — EntitlementsFor replaces it with
		// the tenant's purchased count — and it is 0 rather than a friendly default so a caller that
		// forgot to go through EntitlementsFor fails closed (no targets) instead of scanning unpaid.
		// AutonomousPentest is on because a Safe-to-Host audit that never tried to exploit anything
		// is a scanner printout; the fee covers the operator's model cost for that application.
		return PlanLimits{
			Plan: PlanAudit, Label: "Per-application audit", MaxAssets: 0,
			AIEnabled: true, AutonomousPentest: true, AllFrameworks: true,
			ContinuousMonitoring: false, HumanInLoopApply: true,
			APIRatePerMin: 600,
		}
	case PlanGrowth:
		// The "Core" tier: the full deterministic engine PLUS the AI Security Engineer.
		//
		// AI USED TO BE ENTERPRISE-ONLY, AND THAT WAS THE WRONG SHAPE FOR THIS BUYER. The product IS the
		// two agents; putting them behind "talk to us" meant a company that decides in a week and pays by
		// card could not buy the thing we sell. So the engineer is now purchasable self-serve, and the
		// AI Pentester rides the existing "+pentest" add-on (Entitlements unlocks AutonomousPentest for
		// any plan carrying the token) — which is why this needed no new plan key and no change to the
		// "scale"/"custom" aliases that already resolve to Enterprise.
		//
		// The economic invariant is unchanged in KIND, only in where the line sits: Free still never
		// spends operator LLM budget, and a tenant's own key still works on any plan (§18.5). What moved
		// is that a PAYING self-serve tier now funds the operator model, which is what the price covers.
		return PlanLimits{
			Plan: PlanGrowth, Label: "Core", MaxAssets: 25,
			AIEnabled: true, AutonomousPentest: false, AllFrameworks: true,
			ContinuousMonitoring: true, HumanInLoopApply: true,
			APIRatePerMin: 600, // 10 req/s sustained — ample for CI + dashboards
		}
	default:
		// Free: everything the deterministic engine does, on demand, capped by asset count.
		//
		// AllFrameworks and HumanInLoopApply were declared false here and enforced NOWHERE, so Free
		// tenants had both in practice while the pricing page said they did not. Rather than take them
		// away — they cost us almost nothing and they are most of what convinces an evaluator — the
		// declaration now matches what the product actually does.
		//
		// ContinuousMonitoring stays false and is now genuinely enforced (scheduler.Tick). It is the
		// one limit with a real marginal cost: a sandbox scan per asset, per tick, per tenant, with
		// signups unbounded. Free keeps on-demand scanning; what it does not get is the unattended
		// heartbeat.
		//
		// A declared-but-unenforced limit is worse than either choice. It quietly becomes a claim on
		// the pricing page and a "no" in any surface that reads it, while the code does the opposite.
		return PlanLimits{
			Plan: PlanFree, Label: "Free", MaxAssets: 2,
			AIEnabled: false, AutonomousPentest: false, AllFrameworks: true,
			ContinuousMonitoring: false, HumanInLoopApply: true,
			APIRatePerMin: 120, // 2 req/s sustained — plenty to evaluate, blocks scripted abuse
		}
	}
}
