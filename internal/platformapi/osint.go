package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/osint"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
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
	// Detection lift: an OSINT-discovered internet-exposed host on the ORG'S OWN domains becomes a
	// monitored asset, so the engine actively scans the shadow surface next pass (OSINT → scan loop).
	pivoted := d.pivotExposedHosts(r.Context(), tenantID, snap)
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("osint assessed", "osint",
			map[string]any{"tenant_id": tenantID, "org": snap.Org, "findings": stored, "assets_pivoted": pivoted}, "OSINT snapshot ingest")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": snap.Org, "findings_detected": stored, "assets_pivoted": pivoted, "findings": findings})
}

// pivotExposedHosts promotes OSINT-discovered, internet-exposed, UNMONITORED hosts to monitored assets
// so the engine actively scans them. Grounded guard (§10): only hosts that are at/under one of the
// org's declared snapshot domains are pivoted (we never auto-scan infra the org didn't claim), and the
// host is public-screened. Idempotent (skips an existing (type,target)). Returns the count created.
func (d Deps) pivotExposedHosts(ctx context.Context, tenantID string, snap osint.Snapshot) int {
	if len(snap.ExposedHosts) == 0 || len(snap.Domains) == 0 {
		return 0
	}
	existing, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return 0
	}
	have := map[string]bool{}
	for _, a := range existing {
		have[strings.ToLower(a.Type+"|"+strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(a.Target, "https://"), "http://"), "/"))] = true
	}
	created := 0
	for _, h := range snap.ExposedHosts {
		host := strings.ToLower(strings.TrimSpace(h.Host))
		if host == "" || h.InScope || !hostUnderDomains(host, snap.Domains) {
			continue
		}
		if err := screenPublicHost(host); err != nil {
			continue // never auto-monitor a private/reserved host
		}
		if ip := net.ParseIP(strings.TrimSpace(h.IP)); ip != nil && !isPublicIP(ip) {
			continue // the observed IP is private/internal — not a public scan target
		}
		// A web service → a web_application target; otherwise track the host as a domain asset.
		at := types.AssetDomain
		target := host
		if hasWebService(h.Services) {
			at = types.AssetWebApplication
			target = "https://" + host
		}
		key := string(at) + "|" + host
		if have[key] {
			continue
		}
		asset := platform.Asset{
			ID: d.newID("ast"), TenantID: tenantID, Type: string(at), Target: target,
			Meta: map[string]string{"source": "osint", "discovered_via": nz(h.Source, "osint")}, DiscoveredAt: time.Now().UTC(),
		}
		if err := d.Store.PutAsset(ctx, asset); err == nil {
			have[key] = true
			created++
		}
	}
	return created
}

func hostUnderDomains(host string, domains []string) bool {
	for _, dn := range domains {
		dn = strings.ToLower(strings.TrimSpace(dn))
		if dn == "" {
			continue
		}
		if host == dn || strings.HasSuffix(host, "."+dn) {
			return true
		}
	}
	return false
}

func hasWebService(services []string) bool {
	for _, s := range services {
		switch strings.ToLower(s) {
		case "http", "https", "http-alt", "ssl/http":
			return true
		}
	}
	return false
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
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
