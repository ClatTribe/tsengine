package platformapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// userAddableAssetTypes are the scan-target types a user can add directly by typing a target string.
// The engine's other types arrive a different way: repository / cloud_account come from a connector's
// Discover (GitHub/GitLab/AWS/…), workspace from an IdP connector, and mobile_application needs a
// bundle (APK/IPA) upload — none of which is a typed target. This is the input path the connectors
// don't cover, so a founder can point the agent at their website / API / domain / IP / image.
var userAddableAssetTypes = map[types.AssetType]bool{
	types.AssetWebApplication: true,
	types.AssetAPI:            true,
	types.AssetDomain:         true,
	types.AssetIPAddress:      true,
	types.AssetContainerImage: true,
}

// handleCreateAsset adds a standalone scan target — the input the connectors don't cover. Tenant-
// scoped; the target is validated + SSRF-screened (no private/loopback/reserved hosts, consistent
// with the public assess guard) so a tenant can't point the scanner at internal infra; the caller
// must attest authorization to scan it (the honest legal gate — we never scan a target the user
// hasn't claimed). The new asset carries no ConnectionID, so the runner's connection-active check is
// permissive on it (missing data) and it flows into the same scan loop as discovered assets. Ledger-recorded.
func (d Deps) handleCreateAsset(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Type       string `json:"type"`
		Target     string `json:"target"`
		Authorized bool   `json:"authorized"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	at := types.AssetType(strings.TrimSpace(body.Type))
	if !userAddableAssetTypes[at] {
		writeJSON(w, http.StatusBadRequest, errBody("type must be one of web_application, api, domain, ip_address, container_image"))
		return
	}
	if !body.Authorized {
		writeJSON(w, http.StatusBadRequest, errBody("confirm you are authorized to scan this target"))
		return
	}
	target, err := normalizeScanTarget(at, body.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	// Idempotent: an identical (type, target) for this tenant returns the existing asset, not a dupe.
	assets, err := d.Store.ListAssets(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	for _, a := range assets {
		if a.Type == string(at) && strings.EqualFold(a.Target, target) {
			writeJSON(w, http.StatusOK, viewAsset(a))
			return
		}
	}
	// Plan asset cap (the economic gate, pkg/platform/plan.go): Free is capped small, Growth
	// expands, Enterprise is unlimited (-1). An over-cap add is refused with 402 so the UI can
	// prompt an upgrade — not a silent failure.
	if lim := d.planLimits(r.Context(), tenantID); lim.MaxAssets >= 0 && len(assets) >= lim.MaxAssets {
		writeJSON(w, http.StatusPaymentRequired, errBody(fmt.Sprintf("the %s plan includes up to %d scan targets — upgrade to add more", lim.Label, lim.MaxAssets)))
		return
	}
	asset := platform.Asset{
		ID:           d.newID("ast"),
		TenantID:     tenantID,
		Type:         string(at),
		Target:       target,
		Meta:         map[string]string{"source": "manual", "authorized": "true"},
		DiscoveredAt: time.Now().UTC(),
	}
	if err := d.Store.PutAsset(r.Context(), asset); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("scan target added", "asset_create",
			map[string]any{"tenant_id": tenantID, "asset_id": asset.ID, "type": string(at), "target": target},
			"scan target added")
	}
	writeJSON(w, http.StatusCreated, viewAsset(asset))
}

// normalizeScanTarget validates + canonicalizes a user-supplied scan target for its asset type and
// refuses non-public hosts (SSRF / internal-infra guard). It reuses the same public-IP and reserved-
// namespace screens as the public assess endpoint so the posture is consistent across both surfaces.
func normalizeScanTarget(at types.AssetType, raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", fmt.Errorf("target is required")
	}
	switch at {
	case types.AssetWebApplication, types.AssetAPI:
		if !strings.Contains(t, "://") {
			t = "https://" + t
		}
		u, err := url.Parse(t)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", fmt.Errorf("enter a valid URL, e.g. https://app.acme.com")
		}
		if err := screenPublicHost(u.Hostname()); err != nil {
			return "", err
		}
		return u.String(), nil
	case types.AssetDomain:
		d := normalizeDomain(t)
		if d == "" {
			return "", fmt.Errorf("enter a valid public domain, e.g. acme.com")
		}
		return d, nil
	case types.AssetIPAddress:
		host := t
		if h, _, err := net.SplitHostPort(t); err == nil {
			host = h
		}
		// accept a bare IP or a CIDR; refuse non-public ranges
		if ip := net.ParseIP(host); ip != nil {
			if !isPublicIP(ip) {
				return "", fmt.Errorf("only public IPs can be scanned (not private/loopback/link-local)")
			}
			return host, nil
		}
		if ip, _, err := net.ParseCIDR(host); err == nil {
			if !isPublicIP(ip) {
				return "", fmt.Errorf("only public IP ranges can be scanned")
			}
			return host, nil
		}
		return "", fmt.Errorf("enter a valid IP address or CIDR, e.g. 203.0.113.10")
	case types.AssetContainerImage:
		// a reference like registry/name:tag — no whitespace, has a name component
		if strings.ContainsAny(t, " \t\n") || len(t) > 512 {
			return "", fmt.Errorf("enter a valid image reference, e.g. ghcr.io/acme/api:1.4.2")
		}
		return t, nil
	}
	return "", fmt.Errorf("unsupported target type")
}

// screenPublicHost rejects a hostname/IP that resolves to (or literally is) a non-public address, or
// sits in a reserved/internal namespace — the same SSRF posture as the public assess endpoint.
func screenPublicHost(host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || host == "localhost" {
		return fmt.Errorf("only public hosts can be scanned")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("only public hosts can be scanned (not private/loopback/link-local)")
		}
		return nil
	}
	for _, s := range reservedSuffixes {
		if strings.HasSuffix(host, s) {
			return fmt.Errorf("only public hosts can be scanned (reserved/internal namespace)")
		}
	}
	return nil
}
