package osint

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// This file holds KEYLESS live collectors — OSINT that needs no API key (and, for crt.sh, no sandbox).
// Certificate Transparency (crt.sh) is the canonical passive subdomain/host source: every public TLS
// cert is logged, so querying it reveals the hosts an org has stood up — for free, no auth. It's a
// plain HTTPS JSON API, so the collector runs host-side (SSRF-screened in the caller) like the public
// assess prober. The keyed sources (Shodan, HIBP) stay the credential-gated half.

// ctRecord is the minimal crt.sh JSON row.
type ctRecord struct {
	NameValue string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// ParseCT turns a crt.sh JSON response for one domain into deduped ExposedHost entries (a host is "in
// scope" only of the queried apex; wildcards and out-of-scope SANs are dropped). Pure + testable — the
// network fetch is injected by CollectCT. Grounded: every host is a real CT-logged name for the domain.
func ParseCT(domain string, body []byte) []ExposedHost {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, "*.")))
	if domain == "" || len(body) == 0 {
		return nil
	}
	var rows []ctRecord
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range rows {
		// name_value may carry several newline-separated names.
		for _, raw := range strings.FieldsFunc(r.NameValue+"\n"+r.CommonName, func(c rune) bool { return c == '\n' || c == ' ' || c == ',' }) {
			h := strings.ToLower(strings.TrimSpace(raw))
			h = strings.TrimPrefix(h, "*.") // a wildcard cert → the bare apex/label
			if h == "" || strings.Contains(h, "*") {
				continue
			}
			if h != domain && !strings.HasSuffix(h, "."+domain) {
				continue // only the org's own subtree (grounding)
			}
			seen[h] = true
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]ExposedHost, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, ExposedHost{Host: h, Services: []string{"https"}, Source: "crtsh"})
	}
	return out
}

// CTQueryURL is the keyless crt.sh JSON endpoint for a domain's subtree.
func CTQueryURL(domain string) string {
	return "https://crt.sh/?q=%25." + strings.ToLower(strings.TrimSpace(domain)) + "&output=json"
}

// Fetcher fetches a URL's body. The caller injects an SSRF-screened, bounded HTTP client (so this
// package stays free of network policy); tests inject a fake.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// CollectCT runs the keyless Certificate-Transparency collector over the org's domains and returns an
// OSINT Snapshot (ExposedHosts) ready for Assess. No API key. A host already in `known` (the monitored
// inventory) is marked InScope so it isn't re-flagged as shadow exposure.
func CollectCT(ctx context.Context, org string, domains []string, known map[string]bool, fetch Fetcher) Snapshot {
	snap := Snapshot{Org: org, Domains: domains}
	seen := map[string]bool{}
	for _, d := range domains {
		body, err := fetch(ctx, CTQueryURL(d))
		if err != nil {
			continue // a single domain's failure never aborts the collection (best-effort)
		}
		for _, h := range ParseCT(d, body) {
			if seen[h.Host] {
				continue
			}
			seen[h.Host] = true
			if known[strings.ToLower(h.Host)] {
				h.InScope = true
			}
			snap.ExposedHosts = append(snap.ExposedHosts, h)
		}
	}
	return snap
}
