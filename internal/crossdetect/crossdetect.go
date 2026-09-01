// Package crossdetect turns a tenant's flat finding list into the cross-asset
// correlation input the platform's "Attack Paths" view needs — the unified
// cross-detection layer (a finding on one surface that bridges, via a concrete
// shared identifier, to a crown jewel on another).
//
// The store keeps findings as one flat list per tenant with no per-asset
// grouping, but correlate.Correlate needs them bucketed by asset (type + target)
// to classify entry points / crown jewels and to bridge across surfaces. This
// package reconstructs that grouping: each finding is bucketed by the asset type
// inferred from the tool that produced it, attaching the real target from the
// tenant's asset inventory where one of that type exists.
//
// It is pure orchestration glue over the existing correlate engine — it adds no
// detection and invents no links (correlate only bridges on a real shared
// entity; §10/§13 hold).
package crossdetect

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Assets reconstructs correlate.Asset buckets from a tenant's asset inventory +
// flat findings. Findings are grouped by inferred asset type; the real target
// from the inventory is attached when an asset of that type exists.
func Assets(assets []platform.Asset, findings []types.Finding) []correlate.Asset {
	// First asset of each type supplies the display target + id.
	targetFor := map[string]string{}
	idFor := map[string]string{}
	for _, a := range assets {
		if _, ok := targetFor[a.Type]; !ok {
			targetFor[a.Type] = a.Target
			idFor[a.Type] = a.ID
		}
	}

	buckets := map[string]*correlate.Asset{}
	var order []string
	for _, f := range findings {
		t := inferType(f)
		b := buckets[t]
		if b == nil {
			b = &correlate.Asset{
				ID:     firstNonEmpty(idFor[t], "asset-"+t),
				Type:   t,
				Target: firstNonEmpty(targetFor[t], endpointHint(f.Endpoint)),
			}
			buckets[t] = b
			order = append(order, t)
		}
		b.Findings = append(b.Findings, correlate.Finding{
			ID:          f.ID,
			Title:       firstNonEmpty(f.Title, f.RuleID),
			Severity:    string(f.Severity),
			Endpoint:    f.Endpoint,
			Tool:        f.Tool,
			Description: descOf(f),
			Verified:    f.VerificationStatus == types.VerificationVerified,
		})
	}

	out := make([]correlate.Asset, 0, len(order))
	for _, t := range order {
		out = append(out, *buckets[t])
	}
	return out
}

// Correlate is the convenience entry point: bucket + correlate in one call.
func Correlate(assets []platform.Asset, findings []types.Finding) []correlate.Chain {
	return correlate.Correlate(Assets(assets, findings))
}

// inferType maps a finding to the asset type it belongs to, so correlate can
// classify entry points (web/api/ip/domain) and crown jewels (cloud_account).
// Tool first, then rule-id namespace for the dependency-class findings.
func inferType(f types.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.Tool)) {
	case "prowler", "cloudfox", "scoutsuite", "scout-suite":
		return "cloud_account"
	case "nuclei", "dalfox", "sqlmap", "wpscan", "httpx", "katana", "ffuf", "hydra":
		return "web_application"
	case "kiterunner", "inql", "schemathesis":
		return "api"
	case "nmap", "naabu":
		return "ip_address"
	case "subfinder", "amass", "dnstwist", "crtsh":
		return "domain"
	case "mobsfscan":
		return "mobile_application"
	case "semgrep", "gitleaks", "trufflehog", "codeql", "checkov", "bandit",
		"trivy", "grype", "dockle", "cosign", "syft", "govulncheck":
		return "repository"
	case "operate":
		return "workspace"
	case "sspm":
		return "saas"
	}
	// rule-id namespace fallback (dependency-health classes, etc.).
	switch r := strings.ToLower(f.RuleID); {
	case strings.HasPrefix(r, "prowler::"):
		return "cloud_account"
	case strings.HasPrefix(r, "sspm::"):
		return "saas"
	case strings.HasPrefix(r, "operate"):
		return "workspace"
	}
	return "repository" // safe default — most engine findings are code/dependency
}

// descOf reproduces the correlate.FromScan behaviour of folding a truncated
// raw_output into the description, so entities embedded in raw tool output
// (ARNs, keys) are extractable.
func descOf(f types.Finding) string {
	desc := f.Description
	if len(f.RawOutput) > 0 {
		raw := string(f.RawOutput)
		if len(raw) > 2000 {
			raw = raw[:2000]
		}
		desc = strings.TrimSpace(desc + " " + raw)
	}
	return desc
}

// endpointHint is a cheap display fallback for a synthetic asset's target.
func endpointHint(ep string) string {
	ep = strings.TrimSpace(ep)
	if i := strings.Index(ep, " @"); i >= 0 { // prowler "<Type> <Name> @<Region>"
		ep = strings.TrimSpace(ep[:i])
	}
	return ep
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
