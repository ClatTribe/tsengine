package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// jirasettings.go is the per-tenant Jira ticketing destination (Bucket B — customer configuration
// via UX). file_ticket remediations land in the tenant's OWN Jira (the operator-env Jira is the
// fallback). BaseURL/Email/Project are plain identifiers; the API token is sealed by the Vault
// before it touches the store (§18.2 inv. 6) and NEVER returned — GET reports only presence.

// handleGetJiraSettings returns the tenant's Jira base/email/project and whether a token is set.
func (d Deps) handleGetJiraSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	resp := map[string]any{"base_url": "", "email": "", "project": "", "has_token": false}
	if t.Jira != nil {
		resp["base_url"], resp["email"], resp["project"] = t.Jira.BaseURL, t.Jira.Email, t.Jira.Project
		resp["has_token"] = t.Jira.HasToken()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePutJiraSettings sets the tenant's Jira destination. An empty api_token keeps the existing
// sealed token (so base/project can change without re-entering it); a base_url of "" clears the
// whole config (revert to the operator fallback). The token is sealed via the Vault.
func (d Deps) handlePutJiraSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		BaseURL  string `json:"base_url"`
		Email    string `json:"email"`
		Project  string `json:"project"`
		APIToken string `json:"api_token"`
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
	base := strings.TrimRight(strings.TrimSpace(body.BaseURL), "/")
	if base == "" { // clear → operator fallback only
		t.Jira = nil
		if perr := d.Store.PutTenant(r.Context(), t); perr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(perr.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"base_url": "", "email": "", "project": "", "has_token": false})
		return
	}
	if !strings.HasPrefix(base, "https://") {
		writeJSON(w, http.StatusBadRequest, errBody("base_url must be an https Jira URL"))
		return
	}
	// The base_url is tenant-controlled and the platform POSTs to it server-side (TenantFiler → connector.Jira),
	// so screen the host: refuse a private/loopback/reserved address (SSRF guard, mirroring /v1/assess). The
	// connector's transport re-screens at dial time, catching a hostname that resolves to / rebinds to internal.
	if u, perr := url.Parse(base); perr != nil || u.Host == "" || screenPublicHost(u.Hostname()) != nil {
		writeJSON(w, http.StatusBadRequest, errBody("base_url must be a public host (not an internal/loopback/metadata address)"))
		return
	}
	if strings.TrimSpace(body.Email) == "" || strings.TrimSpace(body.Project) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("email and project are required"))
		return
	}
	cfg := &platform.JiraConfig{BaseURL: base, Email: strings.TrimSpace(body.Email), Project: strings.TrimSpace(body.Project)}
	if t.Jira != nil {
		cfg.TokenRef = t.Jira.TokenRef // preserve the existing token by default
	}
	if tok := strings.TrimSpace(body.APIToken); tok != "" {
		if d.Vault == nil {
			writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
			return
		}
		ref, serr := d.Vault.Seal(tok)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not seal the API token"))
			return
		}
		cfg.TokenRef = ref
	}
	if cfg.TokenRef == "" {
		writeJSON(w, http.StatusBadRequest, errBody("an api_token is required the first time"))
		return
	}
	t.Jira = cfg
	if perr := d.Store.PutTenant(r.Context(), t); perr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(perr.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("jira destination updated", "jira_config",
			map[string]any{"tenant_id": tenantID, "base_url": cfg.BaseURL, "project": cfg.Project, "has_token": cfg.HasToken()},
			"tenant Jira ticketing configured")
	}
	writeJSON(w, http.StatusOK, map[string]any{"base_url": cfg.BaseURL, "email": cfg.Email, "project": cfg.Project, "has_token": cfg.HasToken()})
}

// ResolveTenantJira opens the tenant's sealed Jira token for the remediate.TenantFiler. ok=false
// (silently) when none is set or the Vault is unavailable → the operator fallback files the ticket.
func (d Deps) ResolveTenantJira(ctx context.Context, tenantID string) (baseURL, email, token, project string, ok bool) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || !t.Jira.HasToken() || d.Vault == nil {
		return "", "", "", "", false
	}
	tok, oerr := d.Vault.Open(t.Jira.TokenRef)
	if oerr != nil || tok == "" {
		return "", "", "", "", false
	}
	return t.Jira.BaseURL, t.Jira.Email, tok, t.Jira.Project, true
}
