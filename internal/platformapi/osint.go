package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/osint"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleIngestOSINT ingests an OSINT snapshot (the attacker's-eye external footprint, normalized from
// theHarvester / SpiderFoot / dnstwist / HIBP / taranis-ai) → grounded findings that flow through the
// same store / unified-issues / compliance / incident machinery as every other signal (ADR 0011).
// Tenant-scoped, LLM-free, grounded — a clean footprint yields zero findings. The live collectors are
// the credential-gated half; this posted-snapshot path works today with no external creds, mirroring
// the SaaS-posture + identity-events ingest.
func (d Deps) handleIngestOSINT(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var snap osint.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid OSINT snapshot: "+err.Error()))
		return
	}

	findings := osint.Assess(snap, osint.Options{})
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		// index-suffixed so rapid newID() calls (UnixNano can repeat in a tight loop) never collide
		f.ID = d.newID("osint") + "-" + strconv.Itoa(i)
		if serr := d.Store.PutFinding(r.Context(), tenantID, f); serr != nil {
			respond(w, nil, serr)
			return
		}
		// Fold the OSINT finding into the compliance posture — a breached credential, a public leak, or an
		// exposed host is a real control gap (GDPR/SOC2/PCI), not just a raw finding.
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	// Open incidents for high-severity OSINT now (the scan-pass reconcile never sees ingested findings).
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("osint assessed", "osint",
			map[string]any{"tenant_id": tenantID, "org": snap.Org, "findings": stored}, "OSINT snapshot ingest")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": snap.Org, "findings_detected": stored, "findings": findings})
}

// osintClassLabel maps an osint:: rule to a human class for the UX summary.
var osintClassLabel = map[string]string{
	"osint::breached-credential": "Breached credentials",
	"osint::leaked-secret":       "Leaked secrets",
	"osint::exposed-host":        "Exposed hosts",
	"osint::typosquat-domain":    "Look-alike domains",
	"osint::data-exposure":       "Public data exposure",
	"osint::advisory":            "Relevant advisories",
}

// handleOSINTView (GET /v1/osint) returns the tenant's OSINT findings + a per-class summary — the
// "External exposure" view. Read-only; the same finding list the unified-issues graph already consumes.
func (d Deps) handleOSINTView(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	findings := make([]types.Finding, 0)
	classes := map[string]int{}
	for _, f := range all {
		if f.Tool != "osint" && !strings.HasPrefix(f.RuleID, "osint::") {
			continue
		}
		findings = append(findings, f)
		label := osintClassLabel[f.RuleID]
		if label == "" {
			label = "Other"
		}
		classes[label]++
	}
	summary := make([]map[string]any, 0, len(classes))
	for _, lbl := range []string{"Breached credentials", "Leaked secrets", "Exposed hosts", "Public data exposure", "Look-alike domains", "Relevant advisories", "Other"} {
		if n := classes[lbl]; n > 0 {
			summary = append(summary, map[string]any{"label": lbl, "count": n})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": len(findings), "summary": summary, "findings": findings})
}
