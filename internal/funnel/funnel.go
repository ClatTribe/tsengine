// Package funnel computes the five activation rates the business is run on:
//
//	free scan → signup → connect a system → first finding → agent enabled
//
// WHY THIS IS DERIVED, NOT TRACKED. Four of the five stages are already recorded as
// ordinary product state — a Tenant exists, a Connection went active, a Finding was stored,
// an LLM was configured. Nothing needed instrumenting; the numbers were simply never asked
// for. Bolting on a third-party analytics tracker to re-observe facts the database already
// holds would buy worse data (client-side, ad-blocked, sampled) at the price of a data
// processor, a cookie banner and a sub-processor entry — on a product that sells GDPR and
// DPDP compliance and publishes its sub-processor list on its own Trust Center page.
//
// A COHORT, NOT AN EVENT LOG. Stages 2–5 are evaluated over the tenants who SIGNED UP in the
// window, by how far each has since got. That works without an event log, which the platform
// does not have and does not need for this: "of the accounts created in August, what
// fraction have connected something" is the question a founder actually asks. The cost is
// that a tenant who signed up before the window and connected during it is not counted — so
// the window is a cohort definition, and the report says so rather than implying the counts
// are activity in that period.
//
// THREE GROUNDING RULES (§10), each of which the obvious implementation gets wrong:
//
//  1. AN UNMEASURED STAGE IS NOT ZERO. A stage with no data source reports Measured=false and
//     carries the reason. Rendered as 0 it reads as "nobody did this", which is a claim about
//     customers made out of a gap in our own telemetry.
//
//  2. A ZERO DENOMINATOR IS NOT 0%. No tenants in the window means the rate is UNKNOWN, not
//     "everybody dropped off". Printing 0% on an empty cohort is how a quiet fortnight comes
//     to look like a broken product, and it is the single most likely misreading of a funnel.
//
//  3. THE TOP LINK IS UNMEASURABLE BY CHOICE. Free scan → signup cannot be computed, because
//     linking them requires storing WHICH domain each anonymous stranger scanned and matching
//     it against signups. That record — a list of who was evaluating their own security
//     posture, keyed to a domain — is precisely the kind of thing this product tells
//     customers not to keep. The scan VOLUME is counted; the correlation is declined, and the
//     report says it was declined rather than leaving a blank that reads as an oversight.
package funnel

import (
	"sort"
	"strconv"
	"time"
)

// Stage keys. Stable identifiers — a dashboard keys off these, not the labels.
const (
	StageFreeScan     = "free_scan"
	StageSignup       = "signup"
	StageConnect      = "connect"
	StageFirstFinding = "first_finding"
	StageAgentEnabled = "agent_enabled"
)

// Journey is one tenant's progress, assembled by the caller from store state. Zero times mean
// "never happened" — distinct from "happened at the zero instant", which cannot occur here
// because every timestamp originates from a real record's CreatedAt/DiscoveredAt.
type Journey struct {
	TenantID string
	// SignedUpAt is Tenant.CreatedAt — the account exists.
	SignedUpAt time.Time
	// ConnectedAt is the earliest CreatedAt among connections that are ACTIVE. A revoked or
	// degraded connection is deliberately not progress: the funnel measures whether the
	// product can see the customer's estate, and it cannot through a dead connection.
	ConnectedAt time.Time
	// FirstFindingAt is the earliest DiscoveredAt across the tenant's findings — the first
	// moment the product told them something. This is the activation moment that matters;
	// everything before it is setup.
	FirstFindingAt time.Time
	// AgentEnabled is CURRENT state, not an event: the tenant configured an LLM, or their plan
	// entitles the agent. There is no timestamp on either, so unlike the stages above this one
	// cannot be windowed — which is exactly why the cohort framing is used throughout.
	AgentEnabled bool
	// AgentOwnKey narrows that to the tenants who CONFIGURED one — a deliberate act.
	//
	// The distinction is load-bearing and was found by running this against real data. Paid
	// plans entitle the agent, so on a platform whose customers are mostly on such a plan,
	// AgentEnabled is true for every one of them the instant they sign up. The final stage
	// then reads 100% forever and measures what we sold them, not what they did — which is
	// the one thing a funnel exists to tell apart. Reported as a split rather than by picking
	// one definition, because both numbers are real and they answer different questions:
	// "can the agent run" and "did anyone switch it on".
	AgentOwnKey bool
}

// Stage is one step, with the provenance of its number attached. Basis exists so a reader can
// check the figure rather than trust it — the same discipline the findings carry.
type Stage struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Count    int    `json:"count"`
	Measured bool   `json:"measured"`
	Basis    string `json:"basis"`
	Note     string `json:"note,omitempty"`
}

// Rate is the conversion from one stage to the next.
type Rate struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Pct is 0–100, and is meaningless unless Measured. It is left at 0 when unmeasured for
	// JSON's sake; consumers must branch on Measured, which is why it is not omitempty.
	Pct      float64 `json:"pct"`
	Measured bool    `json:"measured"`
	Note     string  `json:"note,omitempty"`
}

// Report is the whole funnel for one window.
type Report struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	GeneratedAt time.Time `json:"generated_at"`
	// Cohort states, in words, what the numbers are OF. Rendered verbatim: a funnel read as
	// activity-in-period when it is a signup cohort is off by however many old accounts
	// activated this month.
	Cohort string  `json:"cohort"`
	Stages []Stage `json:"stages"`
	Rates  []Rate  `json:"rates"`
}

// Input is everything Compute needs. Assembled by the caller so this package stays pure —
// no store, no clock, no I/O, and therefore testable against exact expectations.
type Input struct {
	From, To time.Time
	Now      time.Time
	// Journeys should be every tenant known to the platform; Compute selects the cohort
	// itself so the windowing rule lives in one place.
	Journeys []Journey
	// FreeScans is the number of public /v1/assess assessments served. ScansMeasured says
	// whether that number means anything — a deployment with no counter wired must report the
	// stage as unmeasured rather than as zero scans (rule 1).
	FreeScans     int
	ScansMeasured bool
	// ScansBasis describes where the count came from, including its limits (an in-process
	// counter resets on restart, and a reader has to know that before trusting a trend).
	ScansBasis string
}

// Compute builds the funnel. Pure.
func Compute(in Input) Report {
	r := Report{
		From: in.From, To: in.To, GeneratedAt: in.Now,
		Cohort: "Accounts created between From and To, measured by how far each has got since. " +
			"Not activity within the window: a tenant who signed up earlier and connected during " +
			"it is not counted here.",
	}

	var signedUp, connected, findings, agents, ownKey int
	for _, j := range in.Journeys {
		if !inWindow(j.SignedUpAt, in.From, in.To) {
			continue
		}
		signedUp++
		// Each stage is counted independently rather than as a strict chain. A tenant can
		// receive a finding from a posted snapshot without an active connection, and treating
		// the stages as a cascade would hide that by capping every later stage at the earlier
		// one — turning a real activation into an apparent drop-off at a step it skipped.
		if !j.ConnectedAt.IsZero() {
			connected++
		}
		if !j.FirstFindingAt.IsZero() {
			findings++
		}
		if j.AgentEnabled {
			agents++
		}
		if j.AgentOwnKey {
			ownKey++
		}
	}

	scanNote := ""
	if !in.ScansMeasured {
		scanNote = "No scan counter is wired in this deployment, so this is UNKNOWN — not zero."
	}
	basis := in.ScansBasis
	if basis == "" {
		basis = "public GET /v1/assess"
	}

	r.Stages = []Stage{
		{Key: StageFreeScan, Label: "Free scan", Count: in.FreeScans, Measured: in.ScansMeasured,
			Basis: basis, Note: scanNote},
		{Key: StageSignup, Label: "Signed up", Count: signedUp, Measured: true,
			Basis: "Tenant.CreatedAt within the window"},
		{Key: StageConnect, Label: "Connected a system", Count: connected, Measured: true,
			Basis: "earliest ACTIVE Connection.CreatedAt (a revoked or degraded connection is not progress)"},
		{Key: StageFirstFinding, Label: "First finding", Count: findings, Measured: true,
			Basis: "earliest Finding.DiscoveredAt for the tenant"},
		{Key: StageAgentEnabled, Label: "Agent enabled", Count: agents, Measured: true,
			Basis: "tenant LLM configured, or plan entitles the agent",
			Note:  agentNote(agents, ownKey)},
	}

	r.Rates = []Rate{
		// Rule 3: this one is refused, and says why. Anything else here would be invented.
		{From: StageFreeScan, To: StageSignup, Measured: false,
			Note: "Not computed. Linking a scan to a signup means storing which domain each " +
				"anonymous visitor scanned — a record of who was checking their own security " +
				"posture. We decline to keep it, so this rate is unavailable by choice, not by " +
				"oversight. Scan VOLUME above is the top-of-funnel signal."},
		rate(StageSignup, StageConnect, signedUp, connected),
		rate(StageConnect, StageFirstFinding, connected, findings),
		rate(StageFirstFinding, StageAgentEnabled, findings, agents),
	}
	return r
}

// agentNote reports the split between tenants who CONFIGURED the agent and those whose plan
// simply entitles it.
//
// Without this the stage silently conflates the two. A paid plan turns the agent on by
// default, so on a platform of paying customers this count equals the signup count and the
// final conversion rate is a permanent 100% — a number that cannot move and therefore cannot
// inform anything. Stating the split is what keeps the stage honest without having to choose
// one definition and discard the other.
func agentNote(total, ownKey int) string {
	base := "Current state, not an event — neither has a timestamp, so this is 'of that cohort, " +
		"how many have the agent on now', which is why the whole report is a cohort. "
	byPlan := total - ownKey
	switch {
	case total == 0:
		return base + "Nobody in this cohort has the agent available."
	case byPlan == 0:
		return base + strconv.Itoa(ownKey) + " configured their own model — every one of these " +
			"is a deliberate act by the customer."
	case ownKey == 0:
		return base + "ALL " + strconv.Itoa(byPlan) + " are entitled by their plan, where the agent " +
			"is on by default; none configured a model themselves. This stage is therefore " +
			"measuring what they were sold, not something they did."
	default:
		return base + strconv.Itoa(ownKey) + " configured their own model (a deliberate act); " +
			strconv.Itoa(byPlan) + " are entitled by their plan, where the agent is on by default " +
			"and no customer action was required."
	}
}

// rate divides, and refuses to when the denominator is empty (rule 2).
func rate(from, to string, den, num int) Rate {
	if den == 0 {
		return Rate{From: from, To: to, Measured: false,
			Note: "No accounts reached " + from + " in this window, so there is nothing to " +
				"convert FROM. Unknown, not 0% — an empty cohort is not a failed one."}
	}
	return Rate{From: from, To: to, Pct: float64(num) / float64(den) * 100, Measured: true}
}

// inWindow is inclusive of From and exclusive of To, so adjacent windows neither
// double-count a tenant nor drop one.
func inWindow(t, from, to time.Time) bool {
	if t.IsZero() {
		return false
	}
	return !t.Before(from) && t.Before(to)
}

// FirstActiveConnection is the ConnectedAt rule, exported so the caller does not restate it
// (a second copy of "which connection counts" is a second thing to get wrong).
func FirstActiveConnection(created []time.Time) time.Time {
	if len(created) == 0 {
		return time.Time{}
	}
	sort.Slice(created, func(i, j int) bool { return created[i].Before(created[j]) })
	return created[0]
}
