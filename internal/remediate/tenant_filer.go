package remediate

import (
	"context"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// JiraResolver returns a tenant's OWN Jira destination (base/email/project + the opened API token,
// resolved from the sealed ref by the caller, which holds the store + Vault). ok=false → the tenant
// has none configured, so the operator fallback files the ticket. Best-effort: a resolver error is
// a silent false.
type JiraResolver func(ctx context.Context, tenantID string) (baseURL, email, token, project string, ok bool)

// TenantFiler routes a file_ticket action to the action's OWN tenant's Jira (the per-tenant
// destination the customer set via UX), falling back to the operator-global filer. This makes
// ticketing multi-tenant: tenant A's tickets land in tenant A's Jira, not the operator's project.
// Implements remediate.Filer.
type TenantFiler struct {
	Resolve  JiraResolver
	Fallback Filer        // operator-global Jira (may be nil → a no-destination ticket is a recorded no-op)
	HTTP     *http.Client // optional override for the per-tenant Jira client (tests); nil → connector.NewJira's SSRF-guarded default
}

// FileTicket files into the tenant's own Jira when configured, else the operator fallback.
func (t TenantFiler) FileTicket(ctx context.Context, a platform.Action) error {
	if t.Resolve != nil {
		if base, email, token, project, ok := t.Resolve(ctx, a.TenantID); ok {
			j := connector.NewJira(base, email, token, project)
			if t.HTTP != nil {
				j.HTTP = t.HTTP
			}
			return j.FileTicket(ctx, a)
		}
	}
	if t.Fallback != nil {
		return t.Fallback.FileTicket(ctx, a)
	}
	return nil
}
