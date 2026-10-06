package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/notify"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// notifysettings.go is the per-tenant notification destination config (Bucket B — customer
// configuration via UX). Each tenant routes its OWN new-incident alerts to its OWN Slack, Teams,
// Discord, PagerDuty rotation and signed webhook; the operator-env channels are only a fallback.
//
// Every destination is a bearer capability (anyone holding a webhook URL can post to the channel;
// anyone holding a PagerDuty routing key can page the rotation), so each is sealed by the Vault
// before it touches the store (§18.2 inv. 6) and NEVER returned to the client — GET reports only
// presence.
//
// Until the non-Slack channels existed here, a customer on Microsoft Teams or PagerDuty could not
// receive their own alerts at all, and an escalation tier "critical → pagerduty" paged the OPERATOR's
// rotation for the customer's incident. The settings page said other channels "are provisioned by
// your administrator", which was true and was the problem.

// notifyChannelRefKeys maps a request field to its key in Tenant.NotifyChannelRefs.
var notifyChannelRefKeys = map[string]string{
	"teams_webhook":         "teams",
	"discord_webhook":       "discord",
	"pagerduty_routing_key": "pagerduty",
	"webhook_url":           "webhook",
	"webhook_secret":        "webhook_secret",
}

func notifySettingsBody(t platform.Tenant) map[string]any {
	return map[string]any{
		"has_slack_webhook": t.HasSlackWebhook(), // kept: the original field, read by older clients
		"channels":          t.NotifyChannelsConfigured(),
		"webhook_signed":    t.NotifyChannelRefs["webhook_secret"] != "",
	}
}

// handleGetNotifySettings reports which channels the tenant has configured — never a value.
func (d Deps) handleGetNotifySettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, notifySettingsBody(t))
}

var pagerDutyKeyRE = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)

// validateNotifyValue checks one destination before it is sealed. A value we cannot deliver to is
// refused at save time: accepted and silently undeliverable, it is a channel the customer believes is
// watching and is not.
func validateNotifyValue(field, v string) error {
	switch field {
	case "slack_webhook":
		if !strings.HasPrefix(v, "https://hooks.slack.com/") {
			return fmt.Errorf("slack_webhook must be an https://hooks.slack.com/ Incoming Webhook URL")
		}
	case "teams_webhook":
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" {
			return fmt.Errorf("teams_webhook must be an https URL")
		}
		h := strings.ToLower(u.Hostname())
		// Teams Incoming Webhooks live on *.webhook.office.com; the Workflows replacement Microsoft is
		// migrating everyone to posts to *.logic.azure.com or *.powerplatform.com.
		if !(strings.HasSuffix(h, ".webhook.office.com") || strings.HasSuffix(h, ".logic.azure.com") ||
			strings.HasSuffix(h, ".powerplatform.com")) {
			return fmt.Errorf("teams_webhook must be a Teams Incoming Webhook (*.webhook.office.com) or a Workflows URL (*.logic.azure.com)")
		}
	case "discord_webhook":
		if !strings.HasPrefix(v, "https://discord.com/api/webhooks/") && !strings.HasPrefix(v, "https://discordapp.com/api/webhooks/") {
			return fmt.Errorf("discord_webhook must be an https://discord.com/api/webhooks/ URL")
		}
	case "pagerduty_routing_key":
		if !pagerDutyKeyRE.MatchString(v) {
			return fmt.Errorf("pagerduty_routing_key must be the 32-character Events API v2 integration key")
		}
	case "webhook_url":
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("webhook_url must be an https URL")
		}
		// Refuse an obviously-internal host now so the customer hears about it; the delivery client
		// also refuses at DIAL time, which is what actually stops a host re-pointed after saving.
		if err := screenPublicHost(u.Hostname()); err != nil {
			return fmt.Errorf("webhook_url must point at a public host")
		}
	case "webhook_secret":
		if len(v) < 16 {
			return fmt.Errorf("webhook_secret must be at least 16 characters")
		}
	}
	return nil
}

// handlePutNotifySettings sets or clears any of the tenant's channels. Each field is a pointer:
// ABSENT leaves that channel unchanged, "" clears it, a value replaces it. (The original endpoint took
// only slack_webhook and an empty string cleared it; a client that sends only teams_webhook must not
// silently wipe the Slack hook, which is why absence and emptiness now mean different things.)
func (d Deps) handlePutNotifySettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body map[string]*string
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	for k := range body {
		if _, ok := notifyChannelRefKeys[k]; !ok && k != "slack_webhook" {
			writeJSON(w, http.StatusBadRequest, errBody("unknown field "+k))
			return
		}
	}
	// Validate everything before sealing or storing anything, so a bad field cannot half-apply.
	for k, v := range body {
		if v == nil {
			continue
		}
		if s := strings.TrimSpace(*v); s != "" {
			if err := validateNotifyValue(k, s); err != nil {
				writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
				return
			}
		}
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	seal := func(s string) (string, bool) {
		if d.Vault == nil {
			writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
			return "", false
		}
		ref, serr := d.Vault.Seal(s)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not seal the destination"))
			return "", false
		}
		return ref, true
	}
	var changed []string
	for k, v := range body {
		if v == nil {
			continue
		}
		s := strings.TrimSpace(*v)
		ref := ""
		if s != "" {
			var ok bool
			if ref, ok = seal(s); !ok {
				return
			}
		}
		if k == "slack_webhook" {
			t.SlackWebhookRef = ref
		} else {
			if t.NotifyChannelRefs == nil {
				t.NotifyChannelRefs = map[string]string{}
			}
			if ref == "" {
				delete(t.NotifyChannelRefs, notifyChannelRefKeys[k])
			} else {
				t.NotifyChannelRefs[notifyChannelRefKeys[k]] = ref
			}
		}
		changed = append(changed, k)
	}
	// A signing secret without a webhook signs nothing; drop it rather than keep a dangling secret.
	if t.NotifyChannelRefs["webhook"] == "" {
		delete(t.NotifyChannelRefs, "webhook_secret")
	}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil && len(changed) > 0 {
		d.Recorder.Record("notification settings updated", "notify_config",
			map[string]any{"tenant_id": tenantID, "changed": changed, "channels": t.NotifyChannelsConfigured()},
			"tenant notification destinations changed")
	}
	writeJSON(w, http.StatusOK, notifySettingsBody(t))
}

// ResolveTenantSlackWebhook opens the tenant's sealed Slack webhook. Kept for callers that only know
// about Slack; new code uses NotifyChannelResolver.
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

// Opener is the half of the Vault delivery needs.
type Opener interface {
	Open(ref string) (string, error)
}

// tenantNotifySecrets opens every configured destination. A ref that will not open is dropped for this
// delivery rather than failing the rest — one corrupt channel must not silence the others.
func tenantNotifySecrets(t platform.Tenant, v Opener) notify.TenantSecrets {
	open := func(ref string) string {
		if ref == "" || v == nil {
			return ""
		}
		s, err := v.Open(ref)
		if err != nil {
			return ""
		}
		return s
	}
	return notify.TenantSecrets{
		Slack:         open(t.SlackWebhookRef),
		Teams:         open(t.NotifyChannelRefs["teams"]),
		Discord:       open(t.NotifyChannelRefs["discord"]),
		PagerDutyKey:  open(t.NotifyChannelRefs["pagerduty"]),
		WebhookURL:    open(t.NotifyChannelRefs["webhook"]),
		WebhookSecret: open(t.NotifyChannelRefs["webhook_secret"]),
	}
}

// NotifyChannelResolver is what cmd/platform wires into the incident routers: per incident, the
// tenant's own destinations, opened from the store. Best-effort — a store or vault error yields no
// tenant channels, and the operator fallback still fires.
func NotifyChannelResolver(st store.Store, v Opener) notify.TenantChannelResolver {
	return func(ctx context.Context, tenantID string) map[string]notify.Alerter {
		t, err := st.GetTenant(ctx, tenantID)
		if err != nil {
			return nil
		}
		return notify.BuildTenantChannels(tenantNotifySecrets(t, v), nil)
	}
}

// testChannelHTTP lets tests reach an httptest server; production leaves it nil so the generic webhook
// keeps its dial-time SSRF guard.
var testChannelHTTP *http.Client

// handleTestNotifyChannel sends one clearly-labelled test alert to ONE named channel and reports what
// happened. A destination that was saved and never exercised is indistinguishable, from the settings
// page, from one that works — until the night it matters. One channel per call, deliberately: a test
// to PagerDuty wakes a real person, so it has to be asked for by name rather than swept up in "test all".
func (d Deps) handleTestNotifyChannel(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Channel string `json:"channel"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if !t.NotifyChannelsConfigured()[body.Channel] {
		writeJSON(w, http.StatusBadRequest, errBody("channel "+body.Channel+" is not configured"))
		return
	}
	a := notify.BuildTenantChannels(tenantNotifySecrets(t, d.Vault), testChannelHTTP)[body.Channel]
	if a == nil {
		writeJSON(w, http.StatusOK, map[string]any{"channel": body.Channel, "ok": false,
			"error": "the stored destination could not be opened; save it again"})
		return
	}
	now := time.Now().UTC()
	inc := platform.Incident{
		ID:       fmt.Sprintf("test-%d", now.UnixNano()), // unique, so PagerDuty never coalesces it into a real incident
		TenantID: tenantID,
		// high, because Teams/Discord/PagerDuty only deliver high and critical by default — a test at a
		// lower severity would be silently dropped by the very gate it is meant to exercise.
		Severity: "high",
		Title:    "[TEST] TensorShield notification test — no action needed",
		RuleID:   "tensorshield::notification-test",
		OpenedAt: now,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := a.IncidentOpened(ctx, inc); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"channel": body.Channel, "ok": false, "error": err.Error()})
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("notification test sent", "notify_test",
			map[string]any{"tenant_id": tenantID, "channel": body.Channel}, "test alert delivered")
	}
	writeJSON(w, http.StatusOK, map[string]any{"channel": body.Channel, "ok": true})
}
