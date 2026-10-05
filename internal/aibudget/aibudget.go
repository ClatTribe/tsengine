// Package aibudget is the capital-allocation PLAN: given a tenant's open exposure and what its AI
// runs have historically bought, which surface should the next tokens go to?
//
// WHY THIS EXISTS. The monthly AI budget (platform.Tenant.MonthlyAIBudgetUSD) is a CAP — it stops
// spending at a ceiling. It never decides WHERE the spend should go. That is the other half of
// Rauch's "capital allocation" question ("what surface should I throw most tokens at?"), and a cap
// cannot answer it: a cap says "stop", a plan says "spend here first". With model reasoning now the
// commodity, the scarce decision is WHERE to point it, and no competitor shows a per-surface answer.
//
// WHAT IT IS, AND IS NOT. This PLANS; it does not spend. It reads the exposure the product already
// proved and the spend the product already metered (platform.AISpend), and returns a ranked, costed
// recommendation. It writes nothing, triggers no run, and changes no budget. The allocation is a
// SUGGESTION a human reads, exactly like a remediation proposal — the agent proposes, the human
// disposes (§18.2 inv. 3 in spirit).
//
// GROUNDED (§10), and the honesty rules are the whole design:
//   - A surface with no open exposure gets ZERO allocation. We never recommend spending on a clean
//     surface to pad a plan.
//   - Yield history is CONTEXT, applied only where it exists. A surface that has proved findings
//     cheaply (low cost-per-verified) is nudged up; a surface with NO metered, proven runs is
//     weighted by exposure ALONE and its Basis says so — "exposure only (no yield history yet)".
//     This mirrors ai-value's rule that a run with unknown cost is never counted as free: here an
//     unknown yield is never counted as a good one.
//   - The plan reports what it is BASED ON per surface, and names what it could not see (no budget
//     set, no model configured, issues it could not attribute to a surface). A ranked list that
//     hides its own gaps is the false-confidence §0 forbids.
//
// DETERMINISTIC + LLM-FREE: identical inputs yield an identical plan. The allocator decides where
// the model's tokens go; it spends none of its own.
package aibudget

import (
	"sort"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Surface is a capital bucket the AI spends tokens on. These three are the token-consuming agent
// surfaces: the cloud specialist, the code specialist, and the Lead's web/API/network/cross-surface
// work. They deliberately match the axis AISpend records (cloud, code, and estate+issue → web), so
// a recommendation can be compared against what was actually spent.
const (
	SurfaceCloud = "cloud"
	SurfaceCode  = "code"
	SurfaceWeb   = "web"
)

// Bucket is one surface's exposure, yield history, and the resulting recommendation.
type Bucket struct {
	Surface    string `json:"surface"`
	OpenIssues int    `json:"open_issues"`
	// Exposure is the sum over this surface's open issues of RiskWeight(severity, data-tier) times an
	// exploitation multiplier (KEV / observed-in-the-wild raise it). It is the grounded measure of how
	// much unaddressed, reachable risk lives on this surface right now.
	Exposure int `json:"exposure"`
	// Yield history, from metered AI runs on this surface (platform.AISpend):
	Runs            int      `json:"runs"`
	Verified        int      `json:"verified"`
	USDKnown        float64  `json:"usd_known"`
	UnknownCostRuns int      `json:"unknown_cost_runs"`
	CostPerVerified *float64 `json:"cost_per_verified,omitempty"` // nil when it cannot be known (see below)
	// The plan:
	SharePct       int     `json:"share_pct"`                 // recommended share of the budget, 0..100
	RecommendedUSD float64 `json:"recommended_usd,omitempty"` // SharePct of the monthly budget; 0 if no budget set
	Basis          string  `json:"basis"`                     // how this bucket's share was decided
}

// Plan is the full allocation across surfaces plus the honesty notes.
type Plan struct {
	MonthlyBudgetUSD   float64  `json:"monthly_budget_usd"`
	BudgetSet          bool     `json:"budget_set"`
	Buckets            []Bucket `json:"buckets"`
	AttributedIssues   int      `json:"attributed_issues"`
	UnattributedIssues int      `json:"unattributed_issues"`
	// Notes name what the plan could not see, so a ranked list is never read as complete.
	Notes []string `json:"notes"`
}

// Inputs are everything the plan is computed from — all already in the store, none computed by a model.
type Inputs struct {
	Budget          float64 // Tenant.MonthlyAIBudgetUSD (0 = no cap set)
	ModelConfigured bool    // whether the tenant has an agent model; no model → no AI runs at all
	OpenIssues      []crossdetect.Issue
	Assets          []platform.Asset
	Spend           []platform.AISpend // metered AI runs, any age (caller may pre-window)
}

// Build computes the allocation plan. Pure; writes nothing.
func Build(in Inputs) Plan {
	p := Plan{MonthlyBudgetUSD: in.Budget, BudgetSet: in.Budget > 0}
	buckets := map[string]*Bucket{
		SurfaceCloud: {Surface: SurfaceCloud},
		SurfaceCode:  {Surface: SurfaceCode},
		SurfaceWeb:   {Surface: SurfaceWeb},
	}

	// 1. Exposure: attribute each open issue to a surface and weight it.
	for _, iss := range in.OpenIssues {
		surface, ok := surfaceForIssue(iss, in.Assets)
		if !ok {
			p.UnattributedIssues++
			continue
		}
		p.AttributedIssues++
		b := buckets[surface]
		b.OpenIssues++
		b.Exposure += issueExposure(iss, in.Assets)
	}

	// 2. Yield history from metered spend.
	for _, s := range in.Spend {
		surface, ok := spendSurface(s.Surface)
		if !ok {
			continue
		}
		b := buckets[surface]
		b.Runs++
		b.Verified += s.Verified
		if s.CostKnown {
			b.USDKnown += s.USD
		} else {
			b.UnknownCostRuns++
		}
	}
	for _, b := range buckets {
		// Cost-per-verified is knowable only when EVERY run's cost was known and the runs proved
		// something. A surface with any unknown-cost run gets no ratio (same rule as ai-value): a
		// partial cost over the whole outcome would understate what the tokens cost.
		if b.Verified > 0 && b.UnknownCostRuns == 0 && b.USDKnown > 0 {
			c := b.USDKnown / float64(b.Verified)
			b.CostPerVerified = &c
		}
	}

	// 3. Allocate. Weight = exposure × yield multiplier (neutral where yield is unknown).
	p.Buckets = allocate(buckets, in.Budget)

	// 4. Honesty notes.
	if !in.ModelConfigured {
		p.Notes = append(p.Notes, "No agent model is configured, so no AI will run regardless of this plan. Configure a model (or a free allowance) to act on it.")
	}
	if !p.BudgetSet {
		p.Notes = append(p.Notes, "No monthly AI budget is set, so the plan gives shares but no dollar amounts. Set MonthlyAIBudgetUSD to get per-surface figures.")
	}
	if p.UnattributedIssues > 0 {
		p.Notes = append(p.Notes, plural(p.UnattributedIssues, "open issue")+" could not be attributed to a surface (no asset's target appears in the endpoint), so they are excluded from the exposure ranking.")
	}
	totalExposure := 0
	for _, b := range p.Buckets {
		totalExposure += b.Exposure
	}
	if totalExposure == 0 {
		p.Notes = append(p.Notes, "No open exposure on any surface, so there is nothing to allocate — not a recommendation to spend evenly.")
	}
	return p
}

// allocate turns per-surface weights into integer shares summing to 100 (when any weight is
// positive) and dollar figures. Surfaces with zero exposure get zero. The yield multiplier only
// nudges a surface whose cost-per-verified is known; where it is unknown the multiplier is 1 and the
// Basis says the share rests on exposure alone.
func allocate(buckets map[string]*Bucket, budget float64) []Bucket {
	order := []string{SurfaceCloud, SurfaceCode, SurfaceWeb}

	// Reference cost-per-verified = the cheapest KNOWN surface, so the multiplier is >=1 and a cheaper
	// surface is favored. Absent any known yield, every multiplier is 1 (pure exposure ranking).
	refCost, haveRef := 0.0, false
	for _, name := range order {
		b := buckets[name]
		if b.CostPerVerified != nil && (!haveRef || *b.CostPerVerified < refCost) {
			refCost, haveRef = *b.CostPerVerified, true
		}
	}

	weights := map[string]float64{}
	var total float64
	for _, name := range order {
		b := buckets[name]
		if b.Exposure <= 0 {
			b.Basis = "no open exposure — nothing to allocate here"
			continue
		}
		w := float64(b.Exposure)
		switch {
		case b.CostPerVerified != nil && haveRef && *b.CostPerVerified > 0:
			// Cheaper-than-reference raises the weight; a surface proving findings at the reference
			// cost is neutral. Capped at 2× so one cheap run cannot swamp a high-exposure surface.
			m := refCost / *b.CostPerVerified
			if m > 2 {
				m = 2
			}
			w *= m
			b.Basis = "exposure × measured yield (cost per proven finding)"
		default:
			b.Basis = "exposure only (no yield history on this surface yet)"
		}
		weights[name] = w
		total += w
	}

	out := make([]Bucket, 0, len(order))
	if total <= 0 {
		for _, name := range order {
			out = append(out, *buckets[name])
		}
		return out
	}
	// Largest-remainder so shares sum to exactly 100.
	type rem struct {
		name string
		frac float64
	}
	var rems []rem
	assigned := 0
	for _, name := range order {
		exact := weights[name] / total * 100
		whole := int(exact)
		buckets[name].SharePct = whole
		assigned += whole
		rems = append(rems, rem{name, exact - float64(whole)})
	}
	sort.SliceStable(rems, func(i, j int) bool { return rems[i].frac > rems[j].frac })
	for i := 0; assigned < 100 && i < len(rems); i++ {
		buckets[rems[i].name].SharePct++
		assigned++
	}
	for _, name := range order {
		b := buckets[name]
		if budget > 0 {
			b.RecommendedUSD = budget * float64(b.SharePct) / 100
		}
		out = append(out, *b)
	}
	return out
}

// issueExposure is the grounded weight of one open issue: its data-tier-adjusted RiskWeight, raised
// when the issue carries an exploitation signal (observed in the wild, or a KEV-listed CVE). These
// are the signals the product already proved — never a model's opinion.
func issueExposure(iss crossdetect.Issue, assets []platform.Asset) int {
	tier := platform.DataTierStandard
	if a, ok := crossdetect.AssetForEndpoint(iss.Endpoint, assets); ok {
		tier = a.DataTier()
	}
	w := crossdetect.RiskWeight(types.Severity(iss.Severity), tier)
	// Observed-in-the-wild is the strongest exploitability signal; a KEV CVE is next. Multiplicative
	// so it scales with severity rather than adding a flat bump a low finding could ride.
	switch {
	case iss.Attacked:
		w = w * 2
	case iss.CVE != "" && issueIsKEV(iss):
		w = w * 3 / 2
	}
	return w
}

// issueIsKEV reports whether the issue is flagged as KEV-listed. The flag rides the crossdetect
// Issue only when a finding under it carried a real KEV listing (threat_intel hook), so this is a
// proven signal, not an inference from the CVE id.
func issueIsKEV(iss crossdetect.Issue) bool { return iss.KEV }

// surfaceForIssue maps an open issue to a capital bucket by the asset it was attributed to. A cloud
// asset → cloud; a repository or container → code; web/api/ip/domain → web. ok=false when the issue
// could not be attributed to any asset (so it is excluded from exposure rather than guessed into a
// bucket).
func surfaceForIssue(iss crossdetect.Issue, assets []platform.Asset) (string, bool) {
	a, ok := crossdetect.AssetForEndpoint(iss.Endpoint, assets)
	if !ok {
		return "", false
	}
	switch types.AssetType(a.Type) {
	case types.AssetCloudAccount:
		return SurfaceCloud, true
	case types.AssetRepository, types.AssetContainerImage:
		return SurfaceCode, true
	case types.AssetWebApplication, types.AssetAPI, types.AssetIPAddress, types.AssetDomain:
		return SurfaceWeb, true
	default:
		return "", false
	}
}

// spendSurface maps an AISpend surface (estate|issue|cloud|code) to a capital bucket. The Lead's
// estate/issue investigation is the web/API/network/cross-surface work, so both map to web.
func spendSurface(s string) (string, bool) {
	switch s {
	case SurfaceCloud:
		return SurfaceCloud, true
	case SurfaceCode:
		return SurfaceCode, true
	case "estate", "issue", SurfaceWeb:
		return SurfaceWeb, true
	default:
		return "", false
	}
}

// plural renders "N thing" / "N things" for a note.
func plural(n int, noun string) string {
	s := strconv.Itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}
