package platformapi

import (
	"encoding/json"
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
	respond(w, map[string]any{
		"issues": issues, "count": len(issues), "raw_findings": len(findings),
		"confirmed": confirmed, "ignored": len(ignored),
	}, nil)
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
