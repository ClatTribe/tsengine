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

	findings, stored, pivoted := d.ingestOSINTSnapshot(r.Context(), tenantID, snap, "OSINT snapshot ingest")
	writeJSON(w, http.StatusOK, map[string]any{"org": snap.Org, "findings_detected": stored, "assets_pivoted": pivoted, "findings": findings})
}

// ingestOSINTSnapshot assesses a snapshot → stores findings + folds them into the compliance posture +
// opens incidents + pivots exposed hosts to monitored assets. Shared by the posted-snapshot ingest and
// the live keyless scan. Returns the findings (never nil) + counts.
func (d Deps) ingestOSINTSnapshot(ctx context.Context, tenantID string, snap osint.Snapshot, recLabel string) ([]types.Finding, int, int) {
	findings := osint.Assess(snap, osint.Options{})
	findings = enrichFindings(findings) // L1.5 parity: enrich platform-native findings like engine-scanned ones (§11)
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("osint") + "-" + strconv.Itoa(i) // index-suffixed so newID() can't collide in a tight loop
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(ctx, tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(ctx, tenantID, saved, nil)
	}
	pivoted := d.pivotExposedHosts(ctx, tenantID, snap)
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("osint assessed", "osint",
			map[string]any{"tenant_id": tenantID, "org": snap.Org, "findings": stored, "assets_pivoted": pivoted}, recLabel)
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	return findings, stored, pivoted
}

// handleOSINTScan (POST /v1/osint/scan) runs a LIVE, KEYLESS OSINT collection — Certificate Transparency
// (crt.sh) over the org's domains — and ingests the result. No API key, no sandbox (crt.sh is a public
// HTTPS JSON API; the fetch is SSRF-screened by the same prober as /v1/assess). Domains come from the
// request body (`{"domains":[...]}`) else are derived from the tenant's domain assets.
func (d Deps) handleOSINTScan(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Domains []string `json:"domains"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	assets, _ := d.Store.ListAssets(r.Context(), tenantID)
	known := map[string]bool{}
	domainSet := map[string]bool{}
	for _, a := range assets {
		host := strings.ToLower(strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(a.Target, "https://"), "http://"), "/"))
		known[host] = true
		if a.Type == string(types.AssetDomain) {
			domainSet[host] = true
		}
	}
	for _, dn := range body.Domains {
		dn = strings.ToLower(strings.TrimSpace(dn))
		if dn != "" {
			domainSet[dn] = true
		}
	}
	domains := make([]string, 0, len(domainSet))
	for dn := range domainSet {
		domains = append(domains, dn)
	}
	if len(domains) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("no domains to scan — pass {\"domains\":[...]} or add a domain asset first"))
		return
	}

	// SSRF-screened, bounded fetch (crt.sh resolves to a public IP, so the guard permits it).
	fetch := func(ctx context.Context, url string) ([]byte, error) {
		client := safeHTTPClient(10 * time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", assessUA)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	}
	snap := osint.CollectCT(r.Context(), tenantID, domains, known, fetch)

	// Dark-web / infostealer: the KEYLESS HudsonRock Cavalier collector over the same domains, reusing the
	// same SSRF-screened fetch (a public HTTPS JSON API like crt.sh). A corporate credential harvested by
	// infostealer malware is the highest-severity OSINT class (SpyCloud/Flare parity). Best-effort.
	stealer := osint.CollectStealerLogs(r.Context(), tenantID, domains, fetch)
	snap.StealerLogs = append(snap.StealerLogs, stealer.StealerLogs...)

	// Best-effort: if the tenant has a connected GitHub org, ALSO run the code-search leak collector over the
	// same domains, reusing THAT connection's token (no new credential — the SaaS-posture GitHub sync pattern).
	// It finds the org's secrets leaked in THIRD-PARTY public repos; the org's OWN repos are excluded (those are
	// the repository asset's job). Gated: no GitHub connection / no vault / no resolvable token → silently skipped.
	ghLeaks := 0
	if d.Vault != nil {
		conns, _ := d.Store.ListConnections(r.Context(), tenantID)
		for i := range conns {
			if conns[i].Kind != platform.ConnGitHub {
				continue
			}
			token, oerr := d.Vault.Open(conns[i].SecretRef)
			if oerr != nil || token == "" {
				break
			}
			ownOrgs := map[string]bool{strings.ToLower(strings.TrimSpace(conns[i].Account)): true}
			ghFetch := func(ctx context.Context, u string) ([]byte, error) {
				client := safeHTTPClient(15 * time.Second)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					return nil, err
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Accept", "application/vnd.github+json")
				req.Header.Set("User-Agent", assessUA)
				resp, err := client.Do(req)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			}
			gh := osint.CollectGitHubLeaks(r.Context(), tenantID, domains, ownOrgs, ghFetch)
			snap.LeakedSecrets = append(snap.LeakedSecrets, gh.LeakedSecrets...)
			ghLeaks = len(gh.LeakedSecrets)
			break
		}
	}

	findings, stored, pivoted := d.ingestOSINTSnapshot(r.Context(), tenantID, snap, "OSINT live CT scan")
	writeJSON(w, http.StatusOK, map[string]any{
		"source": "crtsh+hudsonrock+github-search", "domains_scanned": len(domains), "hosts_discovered": len(snap.ExposedHosts),
		"stealer_logs": len(snap.StealerLogs), "github_leaks": ghLeaks, "findings_detected": stored, "assets_pivoted": pivoted, "findings": findings,
	})
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
	"osint::stealer-log":            "Stealer-log exposure (dark web)",
	"osint::breached-credential":    "Breached credentials",
	"osint::leaked-secret":          "Leaked secrets",
	"osint::exposed-host":           "Exposed hosts",
	"osint::subdomain-takeover":     "Subdomain takeover",
	"osint::typosquat-domain":       "Look-alike domains",
	"osint::data-exposure":          "Public data exposure",
	"osint::cert-unexpected-issuer": "Certificate issues",
	"osint::cert-expired":           "Certificate issues",
	"osint::cert-expiring":          "Certificate issues",
	"osint::advisory":               "Relevant advisories",
}

// osintSummaryOrder is the display order of the summary tiles (every label in osintClassLabel + "Other").
var osintSummaryOrder = []string{
	"Stealer-log exposure (dark web)", "Breached credentials", "Leaked secrets", "Exposed hosts",
	"Subdomain takeover", "Public data exposure", "Look-alike domains", "Certificate issues",
	"Relevant advisories", "Other",
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
	for _, lbl := range osintSummaryOrder {
		if n := classes[lbl]; n > 0 {
			summary = append(summary, map[string]any{"label": lbl, "count": n})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": len(findings), "summary": summary, "findings": findings})
}
