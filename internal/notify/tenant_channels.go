package notify

import (
	"context"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/netguard"
)

// TenantSecrets are a tenant's OWN notification destinations, already opened from their sealed refs
// by the caller (which holds the store + Vault). An empty field means that channel is not configured.
//
// Every one of these is a bearer capability — anyone holding a webhook URL or a PagerDuty routing key
// can post to that channel or page that rotation — which is why they are sealed at rest and why this
// type only ever exists in memory, for the duration of one delivery.
type TenantSecrets struct {
	Slack         string // Slack Incoming Webhook URL
	Teams         string // Microsoft Teams Incoming Webhook / Workflows URL
	Discord       string // Discord webhook URL
	PagerDutyKey  string // PagerDuty Events API v2 routing key
	WebhookURL    string // generic signed-JSON webhook
	WebhookSecret string // HMAC key for WebhookURL; empty → unsigned
}

// TenantChannelResolver returns the alerters a tenant configured for itself, keyed by the SAME channel
// names an escalation policy uses (slack|teams|discord|pagerduty|webhook). An empty map means the
// tenant configured none. Best-effort: a resolver that cannot open a ref drops that channel silently —
// alerting must never block a scan pass, and the operator fallback still fires.
type TenantChannelResolver func(ctx context.Context, tenantID string) map[string]Alerter

// BuildTenantChannels turns opened secrets into alerters.
//
// The generic webhook is the one destination whose host the TENANT chooses freely, so it posts through
// netguard's GuardedClient: the dial itself refuses a non-public address. Validating the URL at save time
// is not enough on its own — a hostname that resolved publicly when it was saved can be re-pointed at
// 169.254.169.254 afterwards, and the request would then come from inside our network. The chat
// channels are validated to their vendors' hosts at save time and pinned to https, so they use a plain
// bounded client; using the guarded one there too would cost nothing but is not what makes them safe.
func BuildTenantChannels(s TenantSecrets, guarded *http.Client) map[string]Alerter {
	plain := &http.Client{Timeout: 10 * time.Second}
	if guarded == nil {
		guarded = netguard.GuardedClient(10 * time.Second)
	}
	out := map[string]Alerter{}
	if s.Slack != "" {
		out["slack"] = &Slack{WebhookURL: s.Slack, HTTP: plain}
	}
	if s.Teams != "" {
		out["teams"] = &Teams{WebhookURL: s.Teams, HTTP: plain}
	}
	if s.Discord != "" {
		out["discord"] = &Discord{WebhookURL: s.Discord, HTTP: plain}
	}
	if s.PagerDutyKey != "" {
		out["pagerduty"] = &PagerDuty{RoutingKey: s.PagerDutyKey, EventsURL: pagerDutyEventsURL, HTTP: plain}
	}
	if s.WebhookURL != "" {
		out["webhook"] = &Webhook{URL: s.WebhookURL, Secret: s.WebhookSecret, MinSeverity: "all", HTTP: guarded}
	}
	return out
}

// ChannelOrder is the stable order channels are delivered and reported in, so a test send and the
// settings page list them the same way every time.
var ChannelOrder = []string{"slack", "teams", "discord", "pagerduty", "webhook"}
