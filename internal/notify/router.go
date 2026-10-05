package notify

import (
	"context"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// WebhookResolver returns a tenant's OWN Slack Incoming Webhook URL (opened from the sealed ref by
// the caller, which holds the store + Vault). ok=false → the tenant has none configured, so only
// the operator fallback fires. Best-effort: a resolver error is a silent (false) — alerting never
// blocks a scan pass.
type WebhookResolver func(ctx context.Context, tenantID string) (webhookURL string, ok bool)

// TenantRouter routes a new-incident heads-up to the incident's OWN tenant's Slack webhook (the
// per-tenant destination the customer set via UX) AND to the operator-global fallback alerter.
// This makes incident notifications multi-tenant: tenant A's incidents go to tenant A's Slack, not
// the operator's single channel. Implements detect.Alerter (IncidentOpened) structurally.
type TenantRouter struct {
	Resolve WebhookResolver // per-tenant Slack webhook lookup (legacy; used only when Channels is nil)
	// Channels resolves EVERY destination the tenant configured for itself (Slack, Teams, Discord,
	// PagerDuty, signed webhook). When set it supersedes Resolve, which only ever knew about Slack —
	// the reason a customer on Teams or PagerDuty could not receive their own alerts at all.
	Channels TenantChannelResolver
	Fallback Alerter      // operator-global channels (MultiAlerter); may be nil
	HTTP     *http.Client // shared client for the per-tenant Slack post; nil → a default
}

// IncidentOpened delivers to every channel the tenant configured and the operator fallback. All are
// best-effort; a per-tenant failure never suppresses the fallback or another tenant channel.
func (r TenantRouter) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	if r.Channels != nil {
		chans := r.Channels(ctx, inc.TenantID)
		for _, name := range ChannelOrder {
			if a := chans[name]; a != nil {
				_ = a.IncidentOpened(ctx, inc) // best-effort, per channel
			}
		}
	} else if r.Resolve != nil {
		if url, ok := r.Resolve(ctx, inc.TenantID); ok && url != "" {
			client := r.HTTP
			if client == nil {
				client = &http.Client{Timeout: 10 * time.Second}
			}
			_ = (&Slack{WebhookURL: url, HTTP: client}).IncidentOpened(ctx, inc) // best-effort
		}
	}
	if r.Fallback != nil {
		return r.Fallback.IncidentOpened(ctx, inc)
	}
	return nil
}
