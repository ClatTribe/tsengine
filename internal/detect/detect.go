// Package detect is the continuous-monitoring backbone — the deterministic "detect" half
// of detect-&-respond (docs/autonomous-team.md). The scheduler re-scans on a cadence, but
// raw findings get overwritten each pass, so the platform couldn't say what CHANGED. The
// Detector closes that gap: it diffs the current findings against the tenant's open
// incidents and opens an incident when an issue at/above a severity threshold first
// appears, resolves one when its issue stops appearing — timestamped + signed.
//
// It is deterministic + grounded (mirrors operate / cloudengine): no LLM, every incident
// keyed to a real finding (rule + cited entity). The "respond" half is the existing
// remediate + HITL path; this package is the change-detection + incident system-of-record
// it feeds.
package detect

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Store is the slice of the platform store the detector needs.
type Store interface {
	PutIncident(ctx context.Context, i platform.Incident) error
	ListIncidents(ctx context.Context, tenantID string) ([]platform.Incident, error)
}

// Alerter is pinged when a NEW incident opens — the heads-up so a human learns of a new
// at/above-threshold issue immediately, not on their next dashboard visit (satisfied by
// *notify.Slack). Optional + best-effort: a delivery error never fails reconciliation.
type Alerter interface {
	IncidentOpened(ctx context.Context, i platform.Incident) error
}

// Responder is invoked ONCE when a batch of event-driven incidents opens, so the AI security engineer
// INVESTIGATES a new incident the moment it is ingested instead of waiting for the next scheduled scan.
//
// This is the "respond" half of detect-and-respond for the EVENT-DRIVEN paths (identity ATO, cloud
// drift, a runtime attack, a warehouse grant). Alerter tells a human; Responder puts the engineer on
// it. It fires only from OpenFor — the scan path (Reconcile) already triggers the engineer via
// AutoReviewAfterScan, so wiring a responder there too would double-review the same estate.
//
// Optional + best-effort by contract: the implementation must never block reconciliation (it detaches
// its own work) and never return an error that fails the ingest. detect takes no dependency on the LLM
// engineer — the composition root supplies the implementation, exactly like Alerter.
type Responder interface {
	// RespondToIncidents is handed every incident opened in this batch. Fire-and-forget: it must return
	// promptly (kick off async work and return), because the caller is on an ingest request path.
	RespondToIncidents(ctx context.Context, tenantID string, opened []platform.Incident)
}

// SkillVerdict is a Detection Skill's triage annotation for an opening incident (ADR 0017).
// Skill is "name@digest" so provenance is pinned.
type SkillVerdict struct {
	Verdict   string // malicious | suspicious | inconclusive | benign
	Rationale string
	Skill     string
}

// SkillTriager optionally annotates an opening incident with a Detection Skill verdict.
//
// The interface lives here, and returns a local type, so `detect` takes no dependency on the skill
// machinery — the composition root supplies an implementation. It CANNOT veto an incident: the only
// thing it returns is annotation. That is deliberate (see openNew) — a skill is third-party input,
// and a verdict that could suppress an alert would be a mute button on the SOC.
type SkillTriager interface {
	// Triage returns an annotation for f, or ok=false when no skill matched or triage failed.
	// Implementations must be best-effort: never block, never error the pass.
	Triage(ctx context.Context, f types.Finding, siblings []types.Finding) (SkillVerdict, bool)
}

// Detector reconciles a tenant's findings into incidents.
type Detector struct {
	Store     Store
	Recorder  *ledger.Recorder // optional: signs every open/resolve into the ledger
	Alerter   Alerter          // optional: alerts a human when an incident opens
	Responder Responder        // optional: puts the AI engineer on event-driven incidents (OpenFor only)
	Triager   SkillTriager     // optional: annotates an opening incident with a Detection Skill verdict
	Threshold types.Severity   // minimum severity to open an incident (default high)
	// AlertCap bounds how many per-pass incident-opened alerts the Alerter fires. A bulk event (e.g.
	// 300 accounts lose MFA in one IdP export) still OPENS every incident — they're all in the UI for
	// triage — but pages the human at most AlertCap times so a mid-size org isn't hit by an alert
	// storm. 0 = unlimited (back-compat / tests). The incidents beyond the cap open silently.
	AlertCap int
	// ResolveAfterAbsent is how many CONSECUTIVE authoritative passes must miss an issue before its
	// incident resolves. Default 2 — one absence is not evidence of a fix when the scanner itself is
	// non-deterministic (see the hysteresis note in Reconcile). Set 1 to restore resolve-on-first-
	// absence; 0 uses the default.
	ResolveAfterAbsent int
	Now                func() time.Time
	NewID              func() string
	// Suppressed reports whether alerting is suppressed for a tenant at a moment (a maintenance
	// window is active). When true, Reconcile opens NO new incidents and EscalateOverdue pages no
	// one — but resolves still flow. Optional: nil → never suppressed (today's behaviour).
	Suppressed func(ctx context.Context, tenantID string, now time.Time) bool
}

// Result summarizes one reconcile pass.
type Result struct {
	Opened   []platform.Incident
	Resolved []platform.Incident
}

// Reconcile diffs the current findings against the tenant's open incidents:
//   - a finding at/above the threshold whose issue has no open incident → open one;
//   - an open incident whose issue is absent from the current findings → resolve it.
//
// Idempotent: re-running with the same findings opens/resolves nothing. The current
// findings are the authoritative present state (the caller passes the freshly-scanned
// set, not the lingering finding store), so a now-empty scan correctly resolves.
// attacked is the set of finding keys (rule_id|endpoint) observed under attack in
// production (runtime-protection signal, ADR-0007 Phase 0b). Those open an incident
// REGARDLESS of the severity floor — a live exploit attempt is itself urgent — and the
// incident is marked Attacked. Pass nil when there is no runtime signal.
func (d *Detector) Reconcile(ctx context.Context, tenantID string, current []types.Finding, attacked map[string]bool) (Result, error) {
	return d.ReconcileScoped(ctx, tenantID, current, attacked, AllProducers())
}

// ReconcileScoped is Reconcile with the pass's authority stated rather than assumed: it resolves only
// incidents whose PRODUCER this pass actually observed (see coverage.go / ADR 0024 C16).
//
// Reconcile keeps the old signature and passes AllProducers() because some callers genuinely sweep
// everything, and because silently narrowing an existing caller's authority would trade a false
// resolve for a permanent false non-resolve — the same failure pointed the other way, which the
// degraded-pass work already had to learn once.
//
// An uncovered incident is not merely left unresolved: its AbsentPasses is NOT incremented either.
// Counting absences we were never in a position to observe would resolve the incident on schedule
// anyway, just more slowly, which is the bug with a delay rather than a fix.
func (d *Detector) ReconcileScoped(ctx context.Context, tenantID string, current []types.Finding, attacked map[string]bool, cov Coverage) (Result, error) {
	present := d.presentIssues(current, attacked)

	openByKey, err := d.openIncidentsByKey(ctx, tenantID)
	if err != nil {
		return Result{}, err
	}

	res, err := d.openNew(ctx, tenantID, present, openByKey, attacked)
	if err != nil {
		return res, err
	}

	// resolve incidents whose issue is gone — ONLY valid when `current` is the authoritative present
	// state (a full scan pass). Event-driven ingests use OpenFor (open-only) instead, so they never
	// falsely resolve a scan incident whose key they don't carry.
	for key, inc := range openByKey {
		if !cov.Covers(inc.RuleID) {
			// Nothing this pass ran could have re-observed this producer, so its silence carries no
			// information. Leave the incident exactly as it is — status, streak and all.
			continue
		}
		if _, still := present[key]; still {
			// Reappeared: any absence streak is over. Persist the reset so a later gap starts
			// counting from zero rather than inheriting a stale count.
			if inc.AbsentPasses != 0 {
				inc.AbsentPasses = 0
				if err := d.Store.PutIncident(ctx, inc); err != nil {
					return res, err
				}
			}
			continue
		}

		// HYSTERESIS. One absent scan is not proof a vulnerability is gone.
		//
		// Measured against WAVSEP: dalfox on the same unchanged target found 7 distinct vulnerable
		// cases in one run and 9 in the next, SUCCEEDING both times — so nothing appeared in
		// Scan.ToolsFailed and the degraded-pass guard (which covers tools that die) never fired.
		// Four cases flipped between runs. Resolving on a single absence turns each flip into "your
		// vulnerability is fixed", followed by a fresh incident next pass, forever.
		//
		// So absence has to persist across consecutive authoritative passes before it counts as a
		// fix. The cost is a real fix staying open one extra cycle; the alternative is telling a
		// customer a live vulnerability was remediated because a scanner had a quiet run.
		inc.AbsentPasses++
		if inc.AbsentPasses < d.resolveAfterAbsent() {
			if err := d.Store.PutIncident(ctx, inc); err != nil {
				return res, err
			}
			continue
		}

		inc.Status = platform.IncidentResolved
		inc.ResolvedAt = d.now()
		d.record("incident_resolved", inc)
		if err := d.Store.PutIncident(ctx, inc); err != nil {
			return res, err
		}
		res.Resolved = append(res.Resolved, inc)
	}
	return res, nil
}

// OpenFor opens incidents for the present (at/above-threshold or attacked) findings WITHOUT the
// resolve sweep — for event-driven ingest paths (identity / SaaS / runtime). Those findings arrive
// one-shot and are not re-confirmed by a scan pass, so feeding them to Reconcile would falsely resolve
// every scan incident whose key they don't carry. A high identity/SaaS threat should still open a "new
// since last scan" incident the moment it's ingested — that's what this does. Idempotent: a finding
// whose key already has an open incident is skipped.
func (d *Detector) OpenFor(ctx context.Context, tenantID string, current []types.Finding, attacked map[string]bool) (Result, error) {
	present := d.presentIssues(current, attacked)
	openByKey, err := d.openIncidentsByKey(ctx, tenantID)
	if err != nil {
		return Result{}, err
	}
	res, err := d.openNew(ctx, tenantID, present, openByKey, attacked)
	if err != nil {
		return res, err
	}
	// The RESPOND half, event-driven only: put the AI engineer on the batch the moment it opens. Fired
	// here and NOT in Reconcile because the scan path already reviews via AutoReviewAfterScan; doing both
	// would review the same estate twice. Best-effort by the interface's contract — it detaches its own
	// work, so this never blocks the ingest request.
	if d.Responder != nil && len(res.Opened) > 0 {
		d.Responder.RespondToIncidents(ctx, tenantID, res.Opened)
	}
	return res, nil
}

// presentIssues filters findings to the ones that warrant an incident: at/above the severity floor,
// or observed under attack (any severity).
func (d *Detector) presentIssues(current []types.Finding, attacked map[string]bool) map[string]types.Finding {
	present := map[string]types.Finding{}
	for _, f := range current {
		k := Key(f)
		if d.atOrAbove(f.Severity) || attacked[k] {
			present[k] = f
		}
	}
	return present
}

// openIncidentsByKey indexes the tenant's currently-open incidents by their dedup key.
func (d *Detector) openIncidentsByKey(ctx context.Context, tenantID string) (map[string]platform.Incident, error) {
	incidents, err := d.Store.ListIncidents(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	openByKey := map[string]platform.Incident{}
	for _, inc := range incidents {
		if inc.Status == platform.IncidentOpen {
			openByKey[inc.Key] = inc
		}
	}
	return openByKey, nil
}

// openNew opens an incident for each present issue not already open (the shared "open" half of
// Reconcile + OpenFor). Maintenance-window suppression applies to OPENING only.
func (d *Detector) openNew(ctx context.Context, tenantID string, present map[string]types.Finding, openByKey map[string]platform.Incident, attacked map[string]bool) (Result, error) {
	var res Result
	// Maintenance window active → suppress OPENING new incidents (resolves still flow elsewhere, so a
	// fix landing during the window still closes its incident). A planned change-freeze shouldn't trip
	// the SOC.
	if d.Suppressed != nil && d.Suppressed(ctx, tenantID, d.now()) {
		return res, nil
	}
	alerted := 0 // per-pass alert count — bounded by AlertCap to avoid a bulk-event alert storm
	for key, f := range present {
		if _, already := openByKey[key]; already {
			continue
		}
		title := f.Title
		if attacked[key] {
			title = "[under active attack] " + title
		}
		inc := platform.Incident{
			ID: d.id("inc"), TenantID: tenantID, Key: key, RuleID: f.RuleID,
			Title: title, Severity: string(f.Severity), Status: platform.IncidentOpen,
			FindingID: f.ID, Attacked: attacked[key], OpenedAt: d.now(),
			// Carry the FP-control signal so the alert shows confirmed-vs-unconfirmed, never presenting a
			// low-confidence pattern_match as a verified incident (the "no high false positive" rule).
			Verification: string(f.VerificationStatus), Confidence: f.Confidence,
			// Carry the KEV (exploited-in-the-wild) flag the L1.5 threat_intel hook stamped, so the SLA
			// layer can apply the BOD 22-01 accelerated resolve clock (SLAPolicy.KEVResolveHours).
			KEV: f.ThreatIntel != nil && f.ThreatIntel.KEV != nil && f.ThreatIntel.KEV.Listed,
			// Ransomware use and CISA's own due date ride alongside, because "exploited in
			// the wild" and "exploited by ransomware operators, remediate by this date" are
			// different urgencies and the SLA layer must be able to tell them apart.
			Ransomware: f.ThreatIntel != nil && f.ThreatIntel.KEV != nil && f.ThreatIntel.KEV.Ransomware,
			KEVDueAt:   kevDueAt(f),
		}
		// Detection Skill triage (ADR 0017): attach the detection engineer's reasoning to the alert so
		// whoever is on shift inherits it instead of rediscovering it.
		//
		// Deliberately placed AFTER the incident is constructed, and structurally unable to prevent
		// it: a verdict only fills annotation fields. A skill is third-party input, so a "benign"
		// verdict must not be able to stop an incident from opening — that would hand anyone who can
		// publish a skill a mute button on the SOC. Best-effort throughout: a triager that errors, or
		// finds no matching skill, leaves the alert exactly as it is today.
		if d.Triager != nil {
			if v, ok := d.Triager.Triage(ctx, f, presentFindings(present)); ok {
				inc.TriageVerdict, inc.TriageRationale, inc.TriageSkill = v.Verdict, v.Rationale, v.Skill
			}
		}
		d.record("incident_opened", inc)
		if err := d.Store.PutIncident(ctx, inc); err != nil {
			return res, err
		}
		// Every incident OPENS (visible in the UI for triage); the pager fires at most AlertCap times
		// per pass so a bulk ingest doesn't storm the on-call. An under-active-attack incident always
		// pages (it's the strongest signal) regardless of the cap.
		if d.Alerter != nil && (d.AlertCap == 0 || alerted < d.AlertCap || attacked[key]) {
			// The incident opens either way — it is real whether or not the heads-up landed — but a
			// page that failed must not consume the cap, or a broken webhook silently spends the
			// budget and suppresses the alerts that would have gone through.
			if err := d.Alerter.IncidentOpened(ctx, inc); err != nil {
				slog.Warn("[detect] incident alert failed", "incident", inc.ID, "tenant", tenantID, "err", err.Error())
			} else {
				alerted++
			}
		}
		res.Opened = append(res.Opened, inc)
	}
	return res, nil
}

// EscalateOverdue re-alerts the tenant's OPEN, UNACKNOWLEDGED incidents that have passed the
// escalation ack window (timed auto-escalation — the MDR "if no one acks within N minutes, page
// again"). It re-fires the Alerter and stamps LastEscalatedAt so each incident re-pings at most
// once per window. ackWindowMins ≤ 0 (no policy / window off) is a no-op. Returns what it re-alerted.
//
// It runs each monitoring pass after Reconcile, so the window is checked at the scan cadence
// (sub-cadence precision isn't promised — an incident escalates on the first pass after its window
// elapses). Best-effort, like the open-time alert: a delivery error never blocks the others.
func (d *Detector) EscalateOverdue(ctx context.Context, tenantID string, ackWindowMins int) ([]platform.Incident, error) {
	if d == nil || ackWindowMins <= 0 {
		return nil, nil
	}
	// Don't page anyone during a maintenance window — the clock keeps running, but no re-alert fires.
	if d.Suppressed != nil && d.Suppressed(ctx, tenantID, d.now()) {
		return nil, nil
	}
	all, err := d.Store.ListIncidents(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var escalated []platform.Incident
	for _, inc := range all {
		if !inc.Overdue(ackWindowMins, d.now()) {
			continue
		}
		// A PAGE THAT DID NOT LAND IS NOT AN ESCALATION. The error was discarded here and
		// LastEscalatedAt stamped regardless, which did three things on a Slack or PagerDuty
		// outage: recorded incident_escalated in the SIGNED ledger, showed the incident as
		// escalated, and — because Overdue allows at most one re-ping per window — SUPPRESSED
		// the retry for a whole window. So the one mechanism that exists to make sure a critical
		// incident is not ignored went quiet precisely when the alerting path was broken, and left
		// an auditable record saying someone had been paged.
		//
		// Still best-effort: a failed page never blocks the other incidents, and it is not an
		// error from this function. It simply is not recorded as having happened, so the next pass
		// tries again — which is the behaviour anyone would expect from a page that did not send.
		if d.Alerter != nil {
			if err := d.Alerter.IncidentOpened(ctx, inc); err != nil {
				slog.Warn("[detect] re-alert FAILED — not recording an escalation; the next pass will retry",
					"incident", inc.ID, "tenant", tenantID, "err", err.Error())
				continue
			}
		}
		inc.LastEscalatedAt = d.now()
		d.record("incident_escalated", inc)
		if err := d.Store.PutIncident(ctx, inc); err != nil {
			return escalated, err
		}
		escalated = append(escalated, inc)
	}
	return escalated, nil
}

// Key is the stable cross-scan identity of an issue: its rule on its cited entity. Finding
// IDs regenerate per scan, so they can't be used; rule+endpoint is the natural dedup key
// (and matches the GRC/runbook grounding — the same entity, the same issue).
func Key(f types.Finding) string { return f.RuleID + "|" + f.Endpoint }

// resolveAfterAbsent is the consecutive-absence threshold, defaulting to 2.
func (d *Detector) resolveAfterAbsent() int {
	if d.ResolveAfterAbsent > 0 {
		return d.ResolveAfterAbsent
	}
	return 2
}

func (d *Detector) atOrAbove(s types.Severity) bool {
	threshold := d.Threshold
	if threshold == "" {
		threshold = types.SeverityHigh
	}
	// types.Severity.Rank is higher = more severe, so "at or above" is rank >= threshold
	return s.Rank() >= threshold.Rank()
}

func (d *Detector) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d *Detector) id(prefix string) string {
	if d.NewID != nil {
		return prefix + "-" + d.NewID()
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// record writes the decision into the signed ledger (nil Recorder → no-op).
func (d *Detector) record(action string, inc platform.Incident) {
	if d.Recorder == nil {
		return
	}
	d.Recorder.Record(action, "detect", map[string]any{
		"incident_id": inc.ID, "tenant_id": inc.TenantID, "key": inc.Key,
		"severity": inc.Severity, "finding_id": inc.FindingID,
	}, inc.Status)
}

// presentFindings flattens the pass's findings into the evidence universe a skill may cite. A
// verdict may only reference findings that were actually observed this pass (§10 grounding).
func presentFindings(present map[string]types.Finding) []types.Finding {
	out := make([]types.Finding, 0, len(present))
	for _, f := range present {
		out = append(out, f)
	}
	// Deterministic order so a prompt (and therefore a verdict) does not vary with map iteration.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// kevDueAt returns CISA's published remediation deadline for a finding's CVE, or the
// zero time when there is none. Nil-safe at every hop: a finding with no threat intel,
// no KEV entry, or no due date simply has no authority-set deadline — which is not the
// same as having a generous one.
// kevDueAt returns CISA's published deadline for the finding's CVE, or the zero time when
// there is none. The zero time never reaches JSON: Incident.KEVDueAt is tagged `omitzero`,
// so "no deadline" serializes as an absent field rather than as year 1 — which a reader
// renders as a deadline that has already passed.
func kevDueAt(f types.Finding) time.Time {
	if f.ThreatIntel == nil || f.ThreatIntel.KEV == nil {
		return time.Time{}
	}
	return f.ThreatIntel.KEV.DueDate
}
