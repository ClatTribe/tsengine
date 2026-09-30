package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/explain"
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
	// CHOKE POINTS — what appears in the MOST paths, so the answer is "fix this one thing" rather than
	// "here are twelve pieces of work". Empty when the paths share nothing, which is a real answer: they
	// are genuinely separate work and pretending otherwise would invent leverage that does not exist.
	choke := crossdetect.ChokePoints(chains)
	if choke == nil {
		choke = []crossdetect.ChokePoint{} // never null — the frontend maps over this
	}
	// The BASIS the correlation ran over. Zero paths is only reassuring if there was something to
	// correlate: Correlate chains findings that bridge between surfaces, so an estate with no findings
	// yields zero paths for the same reason a secure one does. Reporting the input lets the UI say
	// "we correlated N findings and found no chain" instead of "no attack paths — that's good" over
	// an estate that was never scanned (§10).
	respond(w, map[string]any{
		"attack_paths": chains, "count": len(chains),
		"choke_points":        choke,
		"correlated_findings": len(findings),
		"assets_considered":   len(assets),
	}, nil)
}

// handleTriageFunnel returns the auto-triage funnel — the quantified noise reduction: of all
// raw findings, how many the engine handled automatically (exclusion / dedup / suppression)
// before a human had to look. The "% auto-triaged" metric, grounded in the same machinery as
// the issues view. Tenant-scoped.
func (d Deps) handleTriageFunnel(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	excl, err := d.Store.ListExclusionRules(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	rules, err := d.Store.ListIgnoreRules(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	now := time.Now().UTC()
	ignored := make(map[string]bool, len(rules))
	for _, ir := range rules {
		if ir.Suppresses(now) { // a lapsed acceptance no longer hides its issue
			ignored[ir.IssueKey] = true
		}
	}
	respond(w, crossdetect.TriageStats(findings, excl, ignored), nil)
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
	// A rule past its review date no longer suppresses: the issue returns to the active list, and the
	// lapsed rule rides along so the page can say WHO accepted it, why, and when that ran out.
	now := time.Now().UTC()
	ignored := map[string]platform.IgnoreRule{}
	lapsed := map[string]platform.IgnoreRule{}
	for _, ir := range rules {
		if ir.Suppresses(now) {
			ignored[ir.IssueKey] = ir
		} else {
			lapsed[ir.IssueKey] = ir
		}
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
	// Two consumers of the same runtime stream with OPPOSITE needs w.r.t. our own probes:
	//   - AnnotateCompensatingControls WANTS our own blocked probes (a control blocking OUR exploit is
	//     the compensating-control signal), so it reads the RAW events.
	//   - AnnotateRuntime must NOT see our own probes (they would read as a production attack), so it
	//     reads the stream with our probes filtered out.
	// Best-effort — a canary-lookup error leaves the events unfiltered rather than dropping the signal.
	markers, _ := d.tenantProbeMarkers(ctx, tenantID)
	shielded := crossdetect.AnnotateCompensatingControls(issues, events, markers)
	filtered := crossdetect.WithoutOwnProbes(events, markers)
	attacked := crossdetect.AnnotateRuntime(issues, filtered)

	// Live-exploitable fusion (the ACSP "active / reachable / exploitable" lens): combine the
	// runtime-attacked signal with internet-exposure + cross-surface attack-path reachability so the
	// few genuinely-live issues surface above the static-posture noise. Grounded; prioritization
	// only — never blocks (§13).
	assets, _ := d.Store.ListAssets(ctx, tenantID)
	chains := crossdetect.Correlate(assets, findings)
	live := crossdetect.AnnotateLiveRisk(issues, chains)

	// Data-tier prioritization: attribute each issue to a tiered asset and re-rank so the
	// highest-risk issues lead (live first, then a finding on a customer-data asset jumps a finding
	// on a low-sensitivity one). No-op on ranking while every asset is at the default Standard tier.
	issues = crossdetect.PrioritizeByDataTier(issues, assets)
	conns, _ := d.Store.ListConnections(ctx, tenantID)
	issues = crossdetect.AnnotatePlatform(issues, findings, assets, conns)

	// Plain-English explanations — what broke, why it matters here, what to do, how soon. Our reader
	// has no security engineer, so a list of rule ids is a list they cannot act on. Deterministic
	// (model-free), so this is exactly as readable with the AI turned off. Blast radius comes from the
	// chains computed just above, or the explanation says it is untraced — never boilerplate.
	explanations := annotateExplanations(issues, findings, assets, chains)
	if explanations == nil {
		// Never serialize a JSON null into a map the frontend indexes — that is the .map/.filter
		// crash class the null-array guard exists to catch (and did catch this).
		explanations = map[string]explain.Explanation{}
	}

	// The decision behind each listed issue that has one: the in-force rule in the ignored view (so the
	// page can show its review date, or that it has none), the lapsed rule in the active view.
	acceptances := map[string]platform.IgnoreRule{}
	lapsedShown := 0
	for _, i := range issues {
		if ir, ok := ignored[i.Key]; ok {
			acceptances[i.Key] = ir
		}
		if ir, ok := lapsed[i.Key]; ok {
			acceptances[i.Key] = ir
			lapsedShown++
		}
	}

	respond(w, map[string]any{
		"issues": issues, "count": len(issues), "raw_findings": rawCount,
		"explanations": explanations,
		"confirmed":    confirmed, "ignored": len(ignored), "excluded": excludedCount,
		"attacked": attacked, "waf_shielded": shielded, "live": live,
		"acceptances": acceptances, "lapsed": lapsedShown,
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
		Key          string `json:"key"`
		Reason       string `json:"reason"`
		Note         string `json:"note"`
		By           string `json:"by"`
		ReviewInDays int    `json:"review_in_days"`
		ExpiresAt    string `json:"expires_at"` // RFC 3339 or YYYY-MM-DD; alternative to review_in_days
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a non-empty issue 'key' is required"))
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "accepted_risk"
	}
	now := time.Now().UTC()
	ir := platform.IgnoreRule{TenantID: tenantID, IssueKey: body.Key, Reason: reason, Note: body.Note, By: body.By, At: now}
	expires, defaulted, msg := reviewDate(body.ReviewInDays, body.ExpiresAt, ir.NeedsReview(), now)
	if msg != "" {
		writeJSON(w, http.StatusBadRequest, errBody(msg))
		return
	}
	ir.ExpiresAt = expires
	if err := d.Store.PutIgnoreRule(r.Context(), ir); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("issue ignored", "issue_ignore",
			map[string]any{"tenant_id": tenantID, "issue_key": body.Key, "reason": reason, "by": body.By,
				"expires_at": ir.ExpiresAt}, "issue suppressed")
	}
	// review_default_applied tells the caller the date was OURS, not theirs — a default applied
	// silently is a setting the person believes says something it does not.
	writeJSON(w, http.StatusOK, map[string]any{"rule": ir, "review_default_applied": defaulted})
}

// reviewDate resolves when a suppression must be looked at again. A risk decision (needsReview) gets the
// requested date, or the visible default; a false positive gets one only if asked. Every date must lie
// in the future and within the maximum window — a year is the longest any framework tolerates between
// reviews of an accepted risk, and "forever" is not a review.
func reviewDate(days int, at string, needsReview bool, now time.Time) (time.Time, bool, string) {
	var t time.Time
	switch {
	case strings.TrimSpace(at) != "":
		v := strings.TrimSpace(at)
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			if parsed, err = time.Parse("2006-01-02", v); err != nil {
				return time.Time{}, false, "expires_at must be an RFC 3339 time or a YYYY-MM-DD date"
			}
		}
		t = parsed.UTC()
	case days != 0:
		if days < 0 {
			return time.Time{}, false, "review_in_days must be positive"
		}
		t = now.AddDate(0, 0, days)
	case needsReview:
		return now.AddDate(0, 0, platform.DefaultRiskReviewDays), true, ""
	default:
		return time.Time{}, false, "" // a false positive with no date asked for: nothing to review
	}
	if !t.After(now) {
		return time.Time{}, false, "the review date must be in the future"
	}
	if t.After(now.AddDate(0, 0, platform.MaxRiskReviewDays)) {
		return time.Time{}, false, "an accepted risk must be reviewed within a year — choose a date no more than 365 days away"
	}
	return t, false, ""
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
