package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// notifysettings.go is the per-tenant notification destination config (Bucket B — customer
// configuration via UX). Each tenant routes its OWN new-incident heads-ups to its OWN Slack
// Incoming Webhook; the operator-env webhook is only a fallback. A webhook URL is a bearer
// capability (anyone holding it can post to the channel), so it is sealed by the Vault before it
// touches the store (§18.2 inv. 6) and NEVER returned to the client — GET reports only presence.

// handleGetNotifySettings returns whether the tenant has its own Slack webhook configured — never
// the URL itself.
func (d Deps) handleGetNotifySettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"has_slack_webhook": t.HasSlackWebhook()})
}

// handlePutNotifySettings sets (or clears) the tenant's Slack incident webhook. A non-empty
// slack_webhook is sealed via the Vault and stored as a ref; an empty string clears it (revert to
// the operator fallback). The URL is validated as an https Slack-shaped hook before sealing.
func (d Deps) handlePutNotifySettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		SlackWebhook string `json:"slack_webhook"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	hook := strings.TrimSpace(body.SlackWebhook)
	if hook != "" && !strings.HasPrefix(hook, "https://hooks.slack.com/") {
		writeJSON(w, http.StatusBadRequest, errBody("slack_webhook must be an https://hooks.slack.com/ Incoming Webhook URL"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if hook == "" {
		t.SlackWebhookRef = "" // clear → operator fallback only
	} else {
		if d.Vault == nil {
			writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
			return
		}
		ref, serr := d.Vault.Seal(hook)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not seal the webhook"))
			return
		}
		t.SlackWebhookRef = ref
	}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("notification settings updated", "notify_config",
			map[string]any{"tenant_id": tenantID, "has_slack_webhook": t.HasSlackWebhook()},
			"tenant Slack incident webhook configured")
	}
	writeJSON(w, http.StatusOK, map[string]any{"has_slack_webhook": t.HasSlackWebhook()})
}

// ResolveTenantSlackWebhook opens the tenant's sealed Slack webhook for the notify.TenantRouter.
// ok=false (silently) when none is set or the Vault is unavailable → the operator fallback fires.
func (d Deps) ResolveTenantSlackWebhook(ctx context.Context, tenantID string) (string, bool) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || !t.HasSlackWebhook() || d.Vault == nil {
		return "", false
	}
	url, oerr := d.Vault.Open(t.SlackWebhookRef)
	if oerr != nil || url == "" {
		return "", false
	}
	return url, true
}
