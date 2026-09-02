package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/mdm"
	"github.com/ClatTribe/tsengine/internal/netguard"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// mdmsettings.go is the per-tenant DEVICE-MANAGEMENT source (Bucket B — customer configuration via
// UX) and the live sync it enables. Until this, device posture arrived only as a posted snapshot;
// now the tenant names its Kandji / Jamf Pro / Intune, seals the credential, and the inventory is
// fetched — on the Sync button here, and on every monitoring pass (runner.syncDevices). Provider and
// base URL are plain identifiers; every credential is sealed (§18.2 inv. 6) and never returned.

type mdmSettingsView struct {
	Provider        string `json:"provider"`
	BaseURL         string `json:"base_url"`
	HasToken        bool   `json:"has_token"`
	ClientID        string `json:"client_id"`
	HasClientSecret bool   `json:"has_client_secret"`
	// M365Connected tells the Intune case whether there is a Microsoft 365 connection whose token
	// a sync may borrow when no token of its own is set — so the page can say "will use your
	// Microsoft 365 connection" rather than leaving the customer to guess why a tokenless config
	// is accepted.
	M365Connected bool     `json:"m365_connected"`
	Providers     []string `json:"providers"`
}

func (d Deps) mdmView(ctx context.Context, t platform.Tenant) mdmSettingsView {
	v := mdmSettingsView{Providers: mdm.Providers(), M365Connected: d.hasActiveConnection(ctx, t.ID, platform.ConnM365)}
	if t.MDM != nil {
		v.Provider, v.BaseURL, v.ClientID = t.MDM.Provider, t.MDM.BaseURL, t.MDM.ClientID
		v.HasToken, v.HasClientSecret = t.MDM.TokenRef != "", t.MDM.ClientSecretRef != ""
	}
	return v
}

func (d Deps) hasActiveConnection(ctx context.Context, tenantID, kind string) bool {
	conns, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return false
	}
	for _, c := range conns {
		if c.Kind == kind && c.Status == platform.ConnActive {
			return true
		}
	}
	return false
}

// handleGetMDMSettings returns the tenant's device-management source without any credential.
func (d Deps) handleGetMDMSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, d.mdmView(r.Context(), t))
}

// handlePutMDMSettings sets the tenant's device-management source. An empty credential field keeps
// the existing sealed one (so the base URL can change without re-entering it); an empty provider
// clears the whole config. The customer-controlled base URL is SSRF-screened here and re-screened at
// dial time by the guarded client the sync uses.
func (d Deps) handlePutMDMSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Provider     string `json:"provider"`
		BaseURL      string `json:"base_url"`
		APIToken     string `json:"api_token"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	provider := strings.ToLower(strings.TrimSpace(body.Provider))
	if provider == "" { // clear
		t.MDM = nil
		if perr := d.Store.PutTenant(r.Context(), t); perr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(perr.Error()))
			return
		}
		writeJSON(w, http.StatusOK, d.mdmView(r.Context(), t))
		return
	}
	if !mdm.ValidProvider(provider) {
		writeJSON(w, http.StatusBadRequest, errBody("provider must be one of "+strings.Join(mdm.Providers(), ", ")))
		return
	}
	cfg := &platform.MDMConfig{Provider: provider}
	if t.MDM != nil && t.MDM.Provider == provider {
		// preserve sealed credentials by default; a provider change discards them (a Kandji token
		// is not a Jamf token, and keeping it would make the next sync fail confusingly)
		cfg.TokenRef, cfg.ClientID, cfg.ClientSecretRef = t.MDM.TokenRef, t.MDM.ClientID, t.MDM.ClientSecretRef
	}
	base := strings.TrimRight(strings.TrimSpace(body.BaseURL), "/")
	switch provider {
	case platform.MDMKandji, platform.MDMJamf:
		if base == "" {
			writeJSON(w, http.StatusBadRequest, errBody("base_url is required for "+provider+" (your tenant's own URL)"))
			return
		}
		if !strings.HasPrefix(base, "https://") {
			writeJSON(w, http.StatusBadRequest, errBody("base_url must be an https URL"))
			return
		}
		// Tenant-controlled and fetched server-side → screen the host (SSRF guard, as the Jira
		// setting does). The guarded client re-screens at dial time against DNS rebinding.
		if u, perr := url.Parse(base); perr != nil || u.Host == "" || screenPublicHost(u.Hostname()) != nil {
			writeJSON(w, http.StatusBadRequest, errBody("base_url must be a public host (not an internal/loopback/metadata address)"))
			return
		}
		cfg.BaseURL = base
	case platform.MDMIntune:
		cfg.BaseURL = "" // Graph is a fixed host; a customer-supplied one is not honoured
	}
	if id := strings.TrimSpace(body.ClientID); id != "" {
		cfg.ClientID = id
	}
	seal := func(plain, what string) (string, bool) {
		if d.Vault == nil {
			writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
			return "", false
		}
		ref, serr := d.Vault.Seal(plain)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not seal the "+what))
			return "", false
		}
		return ref, true
	}
	if tok := strings.TrimSpace(body.APIToken); tok != "" {
		ref, ok := seal(tok, "API token")
		if !ok {
			return
		}
		cfg.TokenRef = ref
	}
	if sec := strings.TrimSpace(body.ClientSecret); sec != "" {
		ref, ok := seal(sec, "client secret")
		if !ok {
			return
		}
		cfg.ClientSecretRef = ref
	}
	// Refuse a config no sync could authenticate with — at configuration time, where the customer
	// is looking, rather than on a monitoring pass at 3 a.m. Intune may borrow the M365 connection.
	if !cfg.HasCredential() && !(provider == platform.MDMIntune && d.hasActiveConnection(r.Context(), tenantID, platform.ConnM365)) {
		switch provider {
		case platform.MDMJamf:
			writeJSON(w, http.StatusBadRequest, errBody("jamf needs an API client (client_id + client_secret) or an api_token"))
		case platform.MDMIntune:
			writeJSON(w, http.StatusBadRequest, errBody("intune needs a Graph api_token, or a connected Microsoft 365 tenant to use"))
		default:
			writeJSON(w, http.StatusBadRequest, errBody("an api_token is required the first time"))
		}
		return
	}
	t.MDM = cfg
	if perr := d.Store.PutTenant(r.Context(), t); perr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(perr.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("device-management source updated", "mdm_config",
			map[string]any{"tenant_id": tenantID, "provider": cfg.Provider, "base_url": cfg.BaseURL, "has_credential": cfg.HasCredential()},
			"tenant MDM source configured")
	}
	writeJSON(w, http.StatusOK, d.mdmView(r.Context(), t))
}

// MDMFetcherFor builds the device fetcher a tenant's MDM config describes — the one construction
// both the Sync button and the runner's monitoring pass use, so the two doors authenticate the same
// way. Opens sealed credentials through the Vault; for Intune with no token of its own, borrows the
// onboarded Microsoft 365 connection's token (a 403 from Graph is then the honest answer that the
// device-management consent is missing, surfaced as itself).
func (d Deps) MDMFetcherFor(ctx context.Context, t platform.Tenant) (mdm.Fetcher, error) {
	if t.MDM == nil {
		return nil, fmt.Errorf("no device-management source configured")
	}
	if d.Vault == nil {
		return nil, fmt.Errorf("secret vault unavailable")
	}
	o := mdm.Options{Open: d.Vault.Open, HTTP: d.mdmHTTP(), GraphBase: d.GraphAPIBase}
	if t.MDM.Provider == platform.MDMIntune && t.MDM.TokenRef == "" {
		conns, err := d.Store.ListConnections(ctx, t.ID)
		if err == nil {
			for _, c := range conns {
				if c.Kind == platform.ConnM365 && c.Status == platform.ConnActive {
					if tok, oerr := d.Vault.Open(c.SecretRef); oerr == nil {
						o.GraphToken = tok
					}
					break
				}
			}
		}
	}
	return mdm.New(t.MDM, o)
}

// mdmHTTP is the client a live MDM fetch uses: SSRF-guarded in production (the base URL is
// tenant-controlled), overridable for tests.
func (d Deps) mdmHTTP() *http.Client {
	if d.MDMHTTP != nil {
		return d.MDMHTTP
	}
	return netguard.GuardedClient(30 * time.Second)
}

// handleSyncDevices is the LIVE device-posture sync (Bucket A — WE FETCH): read the fleet from the
// configured MDM and hand it to the SAME ingest the posted snapshot uses. The response carries the
// provider's own limits in checks_not_run, because a fleet fetched from Intune that reports zero
// issues has said nothing about screen locks, and the customer has to be told that here.
func (d Deps) handleSyncDevices(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if t.MDM == nil {
		writeJSON(w, http.StatusBadRequest, errBody("configure a device-management source first (Settings → Device management)"))
		return
	}
	f, err := d.MDMFetcherFor(r.Context(), t)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	devices, rep, ferr := f.Fetch(r.Context())
	if ferr != nil {
		// the provider's own error, verbatim — a 401 or a 403 names the fix; a false "0 devices" hides it
		writeJSON(w, http.StatusBadGateway, errBody(ferr.Error()))
		return
	}
	var notes []string
	notes = append(notes, rep.ProviderLimits...)
	if n := len(rep.Unread); n > 0 {
		notes = append(notes, fmt.Sprintf("%d device(s) were listed but could not be fully read, so their settings are unreported: %s", n, strings.Join(capList(rep.Unread, 10), ", ")))
	}
	resp := d.ingestDevices(r.Context(), tenantID, devices, "live "+rep.Provider+" MDM sync", notes)
	resp["provider"] = rep.Provider
	resp["source"] = "live"
	writeJSON(w, http.StatusOK, resp)
}

func capList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("… and %d more", len(s)-n))
}
