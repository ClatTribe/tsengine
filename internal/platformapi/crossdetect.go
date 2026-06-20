package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleAttackPaths returns the tenant's cross-surface attack paths — the unified
// cross-detection view. The engine already correlates across assets (a finding on
// one surface that bridges, via a concrete shared identifier, to a crown jewel on
// another: a leaked key in code → cloud admin; an exposed host → an internal
// pivot); this endpoint surfaces it for the dashboard. Grounded: correlate only
// links on a real shared entity, never a guessed connection (§10).
//
// Tenant-scoped (§18.2 inv. 2): it reads only this tenant's assets + findings.
func (d Deps) handleAttackPaths(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	chains := crossdetect.Correlate(assets, findings)
	if chains == nil {
		chains = []correlate.Chain{} // never null — the frontend maps over this (nil-slice→null guard)
	}
	respond(w, map[string]any{"attack_paths": chains, "count": len(chains)}, nil)
}

// handleIssues returns the tenant's findings de-duplicated into unified issues —
// the "one issue, many signals" view: the same CVE flagged by trivy, grype, and
// govulncheck is ONE confirmed issue, not three rows of noise. Grounded: an
// issue claims only the scanners that actually reported it. Tenant-scoped.
func (d Deps) handleIssues(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	rules, err := d.Store.ListIgnoreRules(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	ignored := map[string]platform.IgnoreRule{}
	for _, ir := range rules {
		ignored[ir.IssueKey] = ir
	}

	// Custom exclusion rules (path/package/rule-id globs) drop matching findings BEFORE
	// they're unified — so excluded noise never becomes an issue at all. Count what was
	// removed so the UI can show "N findings excluded by your rules".
	excl, err := d.Store.ListExclusionRules(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	rawCount := len(findings)
	findings = crossdetect.ApplyExclusions(findings, excl)
	excludedCount := rawCount - len(findings)

	all := crossdetect.UnifiedIssues(findings)
	showIgnored := r.URL.Query().Get("show") == "ignored"

	issues := []crossdetect.Issue{}
	confirmed := 0
	for _, i := range all {
		_, supp := ignored[i.Key]
		if supp != showIgnored {
			continue // default view hides ignored; ?show=ignored shows only those
		}
		issues = append(issues, i)
		if i.Confirmed {
			confirmed++
		}
	}

	// Runtime-protection correlation (ADR-0007 Phase 0): flag issues whose endpoint is
	// being attacked in production per an in-app-firewall signal — observed-in-the-wild.
	events, err := d.Store.ListRuntimeEvents(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	attacked := crossdetect.AnnotateRuntime(issues, events)

	respond(w, map[string]any{
		"issues": issues, "count": len(issues), "raw_findings": rawCount,
		"confirmed": confirmed, "ignored": len(ignored), "excluded": excludedCount, "attacked": attacked,
	}, nil)
}

// handleIngestRuntimeEvents accepts attack observations from an in-app firewall / RASP
// sensor (ADR-0007 Phase 0). It STORES them as a signal — it never blocks (the sensor
// does). Accepts a single event or a batch. Tenant-scoped; each event is stamped with
// the tenant + an id + an arrival time when absent. This is the seam an OSS runtime
// firewall (e.g. Zen) streams its block events into.
func (d Deps) handleIngestRuntimeEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	// Accept either a single event object or an array of them.
	var batch []platform.RuntimeEvent
	if err := json.Unmarshal(raw, &batch); err != nil {
		var one platform.RuntimeEvent
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			writeJSON(w, http.StatusBadRequest, errBody("body must be a runtime event or an array of them"))
			return
		}
		batch = []platform.RuntimeEvent{one}
	}
	now := time.Now().UTC()
	stored := 0
	for _, ev := range batch {
		ev.TenantID = tenantID // never trust a body-supplied tenant (isolation)
		if ev.ID == "" {
			ev.ID = d.newID("rte")
		}
		if ev.OccurredAt.IsZero() {
			ev.OccurredAt = now
		}
		if err := d.Store.PutRuntimeEvent(r.Context(), ev); err != nil {
			respond(w, nil, err)
			return
		}
		stored++
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("runtime events ingested", "runtime_ingest",
			map[string]any{"tenant_id": tenantID, "count": stored}, "in-app firewall signal")
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": stored})
}

// handleListRuntimeEvents returns the tenant's stored runtime-protection events.
func (d Deps) handleListRuntimeEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	events, err := d.Store.ListRuntimeEvents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if events == nil {
		events = []platform.RuntimeEvent{}
	}
	blocked := 0
	for _, e := range events {
		if e.Blocked {
			blocked++
		}
	}
	respond(w, map[string]any{"events": events, "count": len(events), "blocked": blocked}, nil)
}

// handleListExclusions returns the tenant's custom exclusion rules.
func (d Deps) handleListExclusions(w http.ResponseWriter, r *http.Request, tenantID string) {
	rules, err := d.Store.ListExclusionRules(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if rules == nil {
		rules = []platform.ExclusionRule{}
	}
	respond(w, map[string]any{"exclusions": rules, "count": len(rules)}, nil)
}

// validExclField is the allowed set of exclusion match fields.
func validExclField(f string) bool {
	switch f {
	case platform.ExclByRule, platform.ExclByPackage, platform.ExclByPath, platform.ExclByCVE, platform.ExclByAny:
		return true
	}
	return false
}

// handleAddExclusion creates a custom exclusion rule (path/package/rule-id/cve glob).
// Ledger-recorded as a governance decision; reversible via delete. Tenant-scoped.
func (d Deps) handleAddExclusion(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Field   string `json:"field"`
		Pattern string `json:"pattern"`
		Reason  string `json:"reason"`
		Note    string `json:"note"`
		By      string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	body.Field = strings.TrimSpace(body.Field)
	if body.Field == "" {
		body.Field = platform.ExclByAny
	}
	if !validExclField(body.Field) {
		writeJSON(w, http.StatusBadRequest, errBody("field must be one of: rule_id, package, path, cve, any"))
		return
	}
	if strings.TrimSpace(body.Pattern) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a non-empty 'pattern' is required"))
		return
	}
	er := platform.ExclusionRule{
		ID: d.newID("excl"), TenantID: tenantID, Field: body.Field, Pattern: body.Pattern,
		Reason: strings.TrimSpace(body.Reason), Note: body.Note, By: body.By, At: time.Now().UTC(),
	}
	if err := d.Store.PutExclusionRule(r.Context(), er); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("exclusion rule added", "exclusion_add",
			map[string]any{"tenant_id": tenantID, "id": er.ID, "field": er.Field, "pattern": er.Pattern, "by": er.By}, "noise-filter rule added")
	}
	writeJSON(w, http.StatusOK, er)
}

// handleDeleteExclusion removes a custom exclusion rule (so its findings reappear).
func (d Deps) handleDeleteExclusion(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.ID) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a non-empty 'id' is required"))
		return
	}
	if err := d.Store.DeleteExclusionRule(r.Context(), tenantID, body.ID); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("exclusion rule removed", "exclusion_delete",
			map[string]any{"tenant_id": tenantID, "id": body.ID}, "noise-filter rule removed")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": body.ID})
}

// handleIgnoreIssue suppresses a unified issue (false-positive / accepted-risk) —
// the issue-lifecycle control. Keyed by the issue's dedup key so it persists across
// re-scans. Recorded into the ledger as a governance decision (§18.2 inv. 4) and
// reversible via unignore. Tenant-scoped.
func (d Deps) handleIgnoreIssue(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Key    string `json:"key"`
		Reason string `json:"reason"`
		Note   string `json:"note"`
		By     string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a non-empty issue 'key' is required"))
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "accepted_risk"
	}
	ir := platform.IgnoreRule{TenantID: tenantID, IssueKey: body.Key, Reason: reason, Note: body.Note, By: body.By, At: time.Now().UTC()}
	if err := d.Store.PutIgnoreRule(r.Context(), ir); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("issue ignored", "issue_ignore",
			map[string]any{"tenant_id": tenantID, "issue_key": body.Key, "reason": reason, "by": body.By}, "issue suppressed")
	}
	writeJSON(w, http.StatusOK, ir)
}

// handleUnignoreIssue restores a previously-suppressed issue to the active list.
func (d Deps) handleUnignoreIssue(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a non-empty issue 'key' is required"))
		return
	}
	if err := d.Store.DeleteIgnoreRule(r.Context(), tenantID, body.Key); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("issue restored", "issue_unignore",
			map[string]any{"tenant_id": tenantID, "issue_key": body.Key}, "issue suppression removed")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": body.Key})
}
