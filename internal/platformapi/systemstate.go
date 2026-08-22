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
func (d Deps) handleSystemState(w http.ResponseWriter, r *http.Request, tenantID string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"degradations": d.computeDegradations(r.Context(), tenantID),
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
		detail := "Exploitation intelligence (CISA KEV, EPSS) is " + humanDays(age) + " old. " +
			"Anything added to KEV since then is not flagged here: no known-exploited badge, no " +
			"ransomware flag, and no accelerated CISA deadline. Severities below are correct for " +
			"what was known then, not for today."
		if embedded {
			detail += " This deployment is using the snapshot built into the binary — set " +
				"TSENGINE_THREAT_INTEL_CORPUS and run `tsengine corpus refresh` to keep it current."
		} else {
			detail += " The corpus is configured but has not refreshed — check the refresh job can " +
				"reach cisa.gov and first.org."
		}
		out = append(out, Degradation{
			Kind: DegradationThreatIntelStale, Severity: "warning",
			Title:  "Exploitation intelligence is out of date",
			Detail: detail,
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
