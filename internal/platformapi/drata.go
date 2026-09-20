package platformapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/grcexport"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Push-to-Drata: the engine's control posture, written into the customer's Drata as records their
// own tests evaluate. GET/PUT /v1/settings/drata configures it; POST /v1/settings/drata/sync runs it.
//
// The design is Drata's and it is the honest one: we push RECORDS (met/gap per control, with the
// finding count and an evidence link), and the pass/fail TEST over those records is authored in
// Drata's dashboard and mapped to a control there. So the engine never tells Drata a control is
// met — it hands over what it assessed and their test decides. A control the engine has not
// assessed is simply not a record (§10). The API key is sealed like every other tenant credential.

// brandOf names the source stamped on each pushed record: the tenant's name, else the product.
func brandOf(t platform.Tenant) string {
	if strings.TrimSpace(t.Name) != "" {
		return t.Name
	}
	return "TensorShield"
}

func (d Deps) drataGetView(t platform.Tenant) map[string]any {
	v := map[string]any{"configured": false, "has_key": false, "connected": false, "base_url": ""}
	if t.Drata != nil {
		v["has_key"] = t.Drata.HasKey()
		v["configured"] = t.Drata.HasKey()
		v["connected"] = t.Drata.ConnectionID > 0 && t.Drata.ResourceID > 0
		v["workspace_id"] = t.Drata.WorkspaceID
		v["base_url"] = t.Drata.BaseURL
	}
	return v
}

func (d Deps) handleGetDrata(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, d.drataGetView(t))
}

func (d Deps) handlePutDrata(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		APIKey      string `json:"api_key"`
		WorkspaceID int    `json:"workspace_id"`
		BaseURL     string `json:"base_url"`
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
	key := strings.TrimSpace(body.APIKey)
	if key == "" {
		// clear
		t.Drata = nil
		if err := d.Store.PutTenant(r.Context(), t); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, d.drataGetView(t))
		return
	}
	if body.WorkspaceID <= 0 {
		writeJSON(w, http.StatusBadRequest, errBody("workspace_id is required (the Drata workspace to push into)"))
		return
	}
	if body.BaseURL != "" && !validDrataBase(body.BaseURL) {
		writeJSON(w, http.StatusBadRequest, errBody("base_url must be an https URL (http is accepted only for a loopback dev endpoint)"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
		return
	}
	ref, serr := d.Vault.Seal(key)
	if serr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not seal the API key"))
		return
	}
	// Changing the key resets the stored connection ids: a new key may belong to a different Drata
	// tenant, and reusing a stale connection id would push into the wrong place.
	t.Drata = &platform.DrataConfig{KeyRef: ref, WorkspaceID: body.WorkspaceID, BaseURL: strings.TrimRight(body.BaseURL, "/")}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, d.drataGetView(t))
}

// handleSyncDrata pushes the current control posture for every framework into Drata as one full
// state. It is a POST because it spends network I/O against the customer's Drata and changes what
// their dashboard shows.
// validDrataBase accepts an https override, or http only for loopback — the API key is sent to this
// host, so a plaintext endpoint is allowed only for a local dev/test Drata, never a real one.
func validDrataBase(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

func (d Deps) handleSyncDrata(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if !t.Drata.HasKey() {
		writeJSON(w, http.StatusBadRequest, errBody("connect Drata first (set an API key and workspace)"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
		return
	}
	key, oerr := d.Vault.Open(t.Drata.KeyRef)
	if oerr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not open the Drata API key"))
		return
	}

	// Gather posture across every framework the engine maps.
	var states []platform.ControlState
	for _, fw := range grc.Frameworks {
		cs, perr := d.GRC.Posture(r.Context(), tenantID, fw)
		if perr != nil {
			continue
		}
		states = append(states, cs...)
	}
	records := grcexport.Records(states, strings.TrimRight(d.AppURL, "/"), brandOf(t))
	if len(records) == 0 {
		// Nothing assessed → nothing to push. Refuse rather than complete an empty session, which
		// would erase Drata's previous batch and read as "TensorShield reports nothing".
		writeJSON(w, http.StatusConflict, errBody("no assessed controls to push yet — run a scan first"))
		return
	}

	client := &grcexport.Client{BaseURL: t.Drata.BaseURL, APIKey: key}
	conn, cerr := client.EnsureConnection(r.Context(), grcexport.Connection{ConnectionID: t.Drata.ConnectionID, ResourceID: t.Drata.ResourceID}, "TensorShield control posture", t.Drata.WorkspaceID)
	if cerr != nil {
		writeJSON(w, http.StatusBadGateway, errBody("drata: "+cerr.Error()))
		return
	}
	// Persist the connection ids the first time they are minted, so a re-sync reuses them.
	if conn.ConnectionID != t.Drata.ConnectionID || conn.ResourceID != t.Drata.ResourceID {
		t.Drata.ConnectionID, t.Drata.ResourceID = conn.ConnectionID, conn.ResourceID
		_ = d.Store.PutTenant(r.Context(), t)
	}
	res, perr := client.Push(r.Context(), conn, records, time.Now().UTC())
	if perr != nil {
		writeJSON(w, http.StatusBadGateway, errBody("drata: "+perr.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pushed": res.Records, "session_id": res.SessionID, "replaced": res.Replaced, "connection_id": conn.ConnectionID})
}
