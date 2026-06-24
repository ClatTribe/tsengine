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
	Resolve  WebhookResolver // per-tenant webhook lookup (sealed → opened by the caller)
	Fallback Alerter         // operator-global channels (MultiAlerter); may be nil
	HTTP     *http.Client    // shared client for the per-tenant Slack post; nil → a default
}

// IncidentOpened delivers to the tenant's own Slack webhook (if configured) and the operator
// fallback. Both are best-effort; a per-tenant post failure never suppresses the fallback.
func (r TenantRouter) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	if r.Resolve != nil {
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
