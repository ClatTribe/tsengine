package platformapi

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// systemstate.go answers one question for the whole product: is what you are looking at complete?
//
// # Why this exists
//
// Three separate defects shipped with the same mechanism. The backend knew something was wrong and
// the screen did not say so:
//
//   - the kill-switch was engaged and the sidebar read "agent online" (a hardcoded string in a
//     component that never received the state);
//   - a scan failed on infrastructure and the findings list rendered empty with no reason (the page
//     never fetched the job at all);
//   - a remediation failed to deliver and the action sat at "approved" (the field was on an object
//     the page already had, and nothing rendered it).
//
// Three different mechanisms, one shape: THE DEFAULT FOR A NEW DEGRADATION SIGNAL WAS INVISIBLE.
// Each was fixed one at a time, which does nothing for the fourth.
//
// Note what would NOT have caught them. A frontend unit-test framework tests the component you wrote
// against the props you passed it; two of these three were failures to fetch or to pass anything at
// all. The defect lives in the contract between the two halves, so the fix belongs there too.
//
// # The inversion
//
// Degradations are computed HERE, once, from real state, and returned as a list. The shell renders
// whatever is in it. Adding a reason makes it visible by default; hiding one becomes a deliberate act
// someone has to justify, which is the opposite of the arrangement that produced those three bugs.
//
// Grounded (§10): every entry is derived from stored state — the tenant's own halt flag, a real failed
// job with its real error, a connection's actual status. Nothing here infers or predicts. When we
// cannot determine something we do not emit a degradation about it, because "we could not check" is
// not the same claim as "this is broken", and a bar that cries wolf gets ignored exactly like the
// silence it replaced.

// Degradation is one reason the current view may be incomplete or not acting.
type Degradation struct {
	// Kind is the stable machine id. The frontend keys off this, never off the prose.
	Kind string `json:"kind"`
	// Severity orders the list and picks the treatment: critical (we are not protecting you right
	// now), warning (a part of the estate is not covered), info (a supported choice with a caveat).
	Severity string `json:"severity"`
	// Title states what is NOT happening, in the user's terms.
	Title string `json:"title"`
	// Detail says what it means for what they are looking at. This is the part that stops an empty
	// list from reading as "you are clean".
	Detail string `json:"detail"`
	// ActionLabel/ActionHref point at the fix. Empty when there is nothing the user can do from here.
	ActionLabel string `json:"action_label,omitempty"`
	ActionHref  string `json:"action_href,omitempty"`
	// Audience is WHO can act on this (ADR 0022 §2). The threat-intel banner told every tenant to
	// "set TSENGINE_THREAT_INTEL_CORPUS and run `tsengine corpus refresh`" — against a binary they do
	// not have. The corpus is global world-state (§7), so that is an operator's job, and the person
	// reading it could do nothing but worry.
	//
	// A message that reaches one person too many is noise. A message that reaches nobody recreates
	// the silent-signal bug this whole file exists to prevent — so AudienceBoth is the default, and
	// narrowing is the deliberate act.
	Audience string `json:"audience"`
}

// Who a degradation is for. Narrow only when the other reader genuinely cannot act AND does not
// need to know the view may be wrong.
const (
	AudienceBoth     = "both"     // everyone: it changes what the screen means for any reader
	AudienceTenant   = "tenant"   // the customer: their data, their connection, their choice
	AudienceOperator = "operator" // whoever runs the deployment: env, binary, shared corpus
)

// degradationAudience is the assignment for every declared kind. It is a map rather than a field set
// at each call site so the guard test can assert completeness against AllDegradationKinds() — a kind
// added without an audience is a build failure, not a message that quietly reaches no one.
var degradationAudience = map[string]string{
	DegradationHalted:           AudienceBoth,   // the owner halted it; an operator debugging "why is nothing running" needs it too
	DegradationLastScanFailed:   AudienceBoth,   // the tenant's findings are stale; the operator may need to look at the sandbox
	DegradationAIOff:            AudienceTenant, // their plan, their key, their upgrade — an operator cannot add it for them
	DegradationConnectionBroken: AudienceTenant, // their OAuth grant; only they can re-authorise
	DegradationCloudCoverage:    AudienceTenant, // their snapshot is missing fields; their collector posts it
	DegradationThreatIntelStale: AudienceBoth,   // BOTH, with different text — see below
}

// Audience returns who should see this degradation, defaulting to both when a kind has no explicit
// assignment. Defaulting wide is the safe direction: over-showing is noise, under-showing is silence.
func (d Degradation) audienceOrBoth() string {
	if d.Audience != "" {
		return d.Audience
	}
	if a, ok := degradationAudience[d.Kind]; ok {
		return a
	}
	return AudienceBoth
}

// VisibleTo filters a degradation set for one reader. `operator` sees operator+both, everyone else
// sees tenant+both.
func VisibleTo(all []Degradation, isOperator bool) []Degradation {
	out := make([]Degradation, 0, len(all))
	for _, d := range all {
		switch d.audienceOrBoth() {
		case AudienceBoth:
			out = append(out, d)
		case AudienceOperator:
			if isOperator {
				out = append(out, d)
			}
		case AudienceTenant:
			if !isOperator {
				out = append(out, d)
			}
		}
	}
	return out
}

// The kinds. Every one must be produced by computeDegradations and is asserted so by a test — a kind
// declared and never emitted is exactly the silent-signal bug this file exists to prevent.
const (
	DegradationHalted           = "automation_halted"
	DegradationLastScanFailed   = "last_scan_failed"
	DegradationAIOff            = "ai_off"
	DegradationConnectionBroken = "connection_broken"
	// DegradationCloudCoverage: the stored cloud snapshot could not answer something we
	// know how to ask — most often privilege escalation, which needs policy documents
	// (AWS) or IAM bindings (GCP) the snapshot omitted.
	//
	// This is the same shape as the failed-scan case and just as dangerous: with no
	// policies to read the engine reports zero escalation paths, and on an attack-path
	// page zero reads as "nobody can become admin here". The gap was already returned to
	// whoever POSTED the inventory; the person who needs it is the one reading the page
	// days later, and they were getting silence.
	DegradationCloudCoverage = "cloud_coverage_incomplete"
	// DegradationThreatIntelStale: the KEV/EPSS corpus is old enough that the priorities built on
	// it have stopped meaning what they say.
	//
	// This one is not a failure anywhere — it is the DEFAULT. With TSENGINE_THREAT_INTEL_CORPUS
	// unset the engine serves a snapshot compiled into the binary, and refresh is best-effort by
	// design ("a failed fetch keeps the last good corpus, never blocks scans"), so a feed that
	// stopped weeks ago looks exactly like one that ran this morning.
	//
	// What goes wrong is silent and one-directional: every CVE added to KEV since the snapshot is
	// unflagged, so there is no KEV badge, no ransomware flag, no BOD 22-01 SLA acceleration and no
	// CISA due date, and something that became actively exploited last month reads as an ordinary
	// medium. Nothing is WRONG in a way a test could catch — it is the right answer to a question
	// asked of an older world.
	DegradationThreatIntelStale = "threat_intel_stale"
)

// AllDegradationKinds is the closed set, for the guard test and for the frontend's exhaustiveness.
func AllDegradationKinds() []string {
	return []string{
		DegradationHalted,
		DegradationLastScanFailed,
		DegradationAIOff,
		DegradationConnectionBroken,
		DegradationCloudCoverage,
		DegradationThreatIntelStale,
	}
}

var degradationRank = map[string]int{"critical": 0, "warning": 1, "info": 2}

// handleSystemState returns every active reason this tenant's view may be incomplete.
//
// FILTERED SERVER-SIDE, not in the UI (ADR 0022 §2). A tenant should never RECEIVE the operator
// remedy, not merely be prevented from rendering it: shipping "set TSENGINE_THREAT_INTEL_CORPUS" to
// a customer's browser and hiding it with CSS still puts our deployment's internals in their
// devtools, and any future consumer of this endpoint would pick it back up.
func (d Deps) handleSystemState(w http.ResponseWriter, r *http.Request, tenantID string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"degradations": VisibleTo(d.computeDegradations(r.Context(), tenantID), false),
	})
}

// computeDegradations reads real state and returns what is currently wrong. Never nil.
func (d Deps) computeDegradations(ctx context.Context, tenantID string) []Degradation {
	out := []Degradation{}
	t, terr := d.Store.GetTenant(ctx, tenantID)

	// 1. The kill-switch. Deliberate, and the most important thing to reflect: a human chose to stop
	// everything, so any screen implying work is happening contradicts them.
	if terr == nil && t.AgentsHalted {
		out = append(out, Degradation{
			Kind: DegradationHalted, Severity: "critical",
			Title:       "Automation is halted",
			Detail:      "No scans are running and no fixes are being applied. Anything below is from before the halt.",
			ActionLabel: "Resume in Settings", ActionHref: "/settings",
		})
	}

	// 2. The most recent scan failed. THE ONE THAT MATTERS MOST: without it a scan that never ran
	// leaves an empty findings list, and on a security product an empty list reads as "you are clean".
	// The real cause rides along — an operator cannot fix "something went wrong".
	if d.Jobs != nil {
		for _, j := range d.Jobs.List(tenantID) {
			if j.Kind != "rescan" {
				continue
			}
			if j.Status == "failed" {
				out = append(out, Degradation{
					Kind: DegradationLastScanFailed, Severity: "critical",
					Title:       "The last scan did not run",
					Detail:      "Results are from earlier scans, not from this one — an empty result does not mean nothing was found. " + j.Error,
					ActionLabel: "Check connections", ActionHref: "/assets",
				})
			}
			break // only the most recent run speaks for the current state
		}
	}

	// 3. No model configured. Deliberately INFO, not a fault: deterministic-only is a supported choice
	// (predictable cost, or source that may not go to a model). It is suppressed entirely once someone
	// has actually chosen it — telling a customer on every page that their engineer is "off" reframes
	// their own decision as a defect. It keys off CHOSEN rather than the resolved mode, because a free
	// workspace resolves to deterministic without anyone choosing it, and suppressing on mode alone
	// silences the notice for exactly the people it is for.
	if terr == nil && !t.AgentsHalted {
		lim := platform.Entitlements(t.Plan)
		if !lim.AIEnabled && !t.LLM.Usable() && t.AIMode == platform.AIModeUnset {
			out = append(out, Degradation{
				Kind: DegradationAIOff, Severity: "info",
				Title:       "Your AI Security Engineer is off",
				Detail:      "Scanning, correlation and compliance mapping still run. Triage, investigation and proposed fixes need a model.",
				ActionLabel: "Add a key", ActionHref: "/settings",
			})
		}
	}

	// 4. A connection we cannot act through. The runner skips any asset whose connection is not active,
	// so this is silently-reduced coverage: the asset list still shows the asset and nothing scans it.
	if conns, err := d.Store.ListConnections(ctx, tenantID); err == nil {
		broken := 0
		for _, c := range conns {
			if c.Status != platform.ConnActive {
				broken++
			}
		}
		if broken > 0 {
			out = append(out, Degradation{
				Kind: DegradationConnectionBroken, Severity: "warning",
				Title:       plural(broken, "connection is", "connections are") + " not usable",
				Detail:      "Assets behind " + plural(broken, "it", "them") + " are not being scanned. Reconnect to restore coverage.",
				ActionLabel: "Review connections", ActionHref: "/assets",
			})
		}
	}

	// 5. The cloud snapshot could not answer something. Grounded (§10): read from the
	// STORED snapshot's own recorded gaps, never inferred from an empty result — "we found
	// no escalation" and "we could not look for escalation" are different claims and only
	// the snapshot itself knows which one this is.
	if d.CloudSnapshots != nil {
		if snap, ok, err := d.CloudSnapshots.Get(ctx, tenantID); err == nil && ok && len(snap.CoverageGaps) > 0 {
			reasons := make([]string, 0, len(snap.CoverageGaps))
			for k := range snap.CoverageGaps {
				reasons = append(reasons, k)
			}
			sort.Strings(reasons)
			out = append(out, Degradation{
				Kind: DegradationCloudCoverage, Severity: "warning",
				Title: "Part of your cloud was not analysed",
				Detail: "The stored cloud snapshot is missing data needed for: " + strings.Join(reasons, ", ") +
					". An empty result for those means we could not look, not that there is nothing there. " +
					snap.CoverageGaps[reasons[0]],
				ActionLabel: "See cloud", ActionHref: "/cloud",
			})
		}
	}

	// 6. The threat intel behind every priority on screen is old.
	//
	// Tenant-independent — the corpus is world state shared by everyone (§7) — but it belongs here
	// because this is the list of reasons the CURRENT VIEW may not mean what it says, and a stale
	// KEV feed changes what every severity on every page is worth.
	if age, stale, embedded := hooks.ThreatIntelAge(nowUTC()); stale {
		// ADR 0022 §2 — the SAME condition, told to two people who can do different things about it.
		//
		// The tenant needs the CONSEQUENCE: every severity on every page may understate a threat
		// discovered since the snapshot. They cannot fix it — the corpus is global world-state (§7)
		// and lives with the binary — so handing them an env var and a shell command was handing
		// them homework they cannot do, in an alarm-coloured band, on the first screen after login.
		//
		// The operator needs the REMEDY, and is the only reader for whom it is actionable.
		consequence := "Exploitation intelligence (the feeds that flag actively-exploited " +
			"vulnerabilities) is " + humanDays(age) + " old. Anything newly known to be under attack " +
			"since then is not badged here, so the severities on this page may be understated. " +
			"Nothing you have connected is affected — this is our data, not yours."
		out = append(out, Degradation{
			Kind: DegradationThreatIntelStale, Severity: "warning", Audience: AudienceTenant,
			Title:  "Threat data is " + humanDays(age) + " old",
			Detail: consequence,
		})

		remedy := "Exploitation intelligence (CISA KEV, EPSS) is " + humanDays(age) + " old. " +
			"Anything added to KEV since then is not flagged: no known-exploited badge, no " +
			"ransomware flag, and no accelerated CISA deadline. Severities are correct for what was " +
			"known then, not for today."
		if embedded {
			remedy += " This deployment is using the snapshot built into the binary — set " +
				"TSENGINE_THREAT_INTEL_CORPUS and run `tsengine corpus refresh` to keep it current."
		} else {
			remedy += " The corpus is configured but has not refreshed — check the refresh job can " +
				"reach cisa.gov and first.org."
		}
		out = append(out, Degradation{
			Kind: DegradationThreatIntelStale, Severity: "warning", Audience: AudienceOperator,
			Title:  "Exploitation intelligence is out of date",
			Detail: remedy,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return degradationRank[out[i].Severity] < degradationRank[out[j].Severity]
	})
	return out
}

// humanDays renders an age the way the sentence needs to read.
func humanDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days <= 0:
		return "of unknown age"
	case days == 1:
		return "1 day"
	default:
		return itoa(days) + " days"
	}
}

// nowUTC is a variable so the guard test can drive staleness from a fixed clock rather than
// depending on when the suite happens to run.
var nowUTC = func() time.Time { return time.Now().UTC() }

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}
