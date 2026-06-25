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

// Detector reconciles a tenant's findings into incidents.
type Detector struct {
	Store     Store
	Recorder  *ledger.Recorder // optional: signs every open/resolve into the ledger
	Alerter   Alerter          // optional: alerts a human when an incident opens
	Threshold types.Severity   // minimum severity to open an incident (default high)
	Now       func() time.Time
	NewID     func() string
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
		if _, still := present[key]; still {
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
	return d.openNew(ctx, tenantID, present, openByKey, attacked)
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
		}
		d.record("incident_opened", inc)
		if err := d.Store.PutIncident(ctx, inc); err != nil {
			return res, err
		}
		if d.Alerter != nil {
			_ = d.Alerter.IncidentOpened(ctx, inc) // best-effort; never fails the pass
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
		if d.Alerter != nil {
			_ = d.Alerter.IncidentOpened(ctx, inc) // best-effort re-alert (the "page again")
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
