package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tlsscan"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleTLSScan (POST /v1/tls/scan) runs the host-side TLS/SSL posture core over a posted host, or — when
// none is given — over the tenant's web/domain/api/ip asset targets. Host-side, no sandbox, SSRF-screened
// exactly like /v1/osint/scan (refuses private/loopback IPs). Findings are stored into the same store so
// they flow through the L1.5 hooks (→ crypto compliance mapping) + issues/grc/hitl like any finding.
// The deep cipher/TLS-vuln enumeration (testssl.sh/sslyze) stays the gated sandbox half (honest, §13).
func (d Deps) handleTLSScan(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Host string `json:"host"`
	}
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	_ = json.Unmarshal(raw, &body)

	hosts := []string{}
	if h := strings.TrimSpace(body.Host); h != "" {
		hosts = append(hosts, h)
	} else {
		// Default: the tenant's TLS-bearing asset targets.
		assets, _ := d.Store.ListAssets(r.Context(), tenantID)
		seen := map[string]bool{}
		for _, a := range assets {
			switch a.Type {
			case "web_application", "domain", "api", "ip_address":
				if h := hostFromTarget(a.Target); h != "" && !seen[h] {
					seen[h] = true
					hosts = append(hosts, h)
				}
			}
		}
	}
	if len(hosts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []types.Finding{}, "scanned": 0,
			"note": "No host given and no web/domain/api/ip asset to scan. Pass {\"host\":\"example.com\"}."})
		return
	}

	saved := []types.Finding{}
	scanned, skipped := 0, []string{}
	for _, h := range hosts {
		ip, ok := tlsResolveAllowed(r.Context(), h)
		if !ok {
			skipped = append(skipped, h)
			continue
		}
		// Pin the handshake to the IP we just screened — a rebinding DNS name can't slip an internal
		// target in between the check and the dial (DNS-rebinding TOCTOU).
		fs, err := tlsscan.AssessPinned(r.Context(), h, ip)
		if err != nil {
			continue // handshake failed → no finding (we don't guess), not fatal
		}
		scanned++
		for _, f := range fs {
			if err := d.Store.PutFinding(r.Context(), tenantID, f); err == nil {
				saved = append(saved, f)
			}
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("tls posture scanned", "tlsscan",
			map[string]any{"tenant_id": tenantID, "scanned": scanned, "findings": len(saved)}, "TLS/SSL posture")
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": saved, "scanned": scanned, "skipped": skipped})
}

// tlsResolveAllowed is the SSRF screen: every resolved IP for the host must be public. It returns ONE
// validated public IP so the caller can dial THAT exact IP (no second resolution) — closing the
// DNS-rebinding TOCTOU, mirroring assess_web.go's safeHTTPClient.
func tlsResolveAllowed(ctx context.Context, host string) (net.IP, bool) {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip, isPublicIP(ip)
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
	if err != nil || len(ips) == 0 {
		return nil, false
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return nil, false // any private IP in the set → reject the whole host
		}
	}
	return ips[0], true // all public; pin the dial to this validated IP
}

func hostFromTarget(target string) string {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
	t = strings.TrimSuffix(t, "/")
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	return t
}
