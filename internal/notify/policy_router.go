package notify

import (
	"context"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// PolicyResolver returns a tenant's incident escalation policy (nil → no policy → default routing).
type PolicyResolver func(ctx context.Context, tenantID string) *platform.EscalationPolicy

// PolicyRouter routes a newly-opened incident through the tenant's escalation matrix (Phase 2 of
// the MDR/SOC escalation gap). When the tenant has an enabled policy whose tiers match the
// incident's severity, the alert goes ONLY to the channels named in the first matching tier
// (severity-aware routing — e.g. critical → pagerduty+slack, high → slack). Otherwise it falls back
// to Default (today's behaviour: the per-tenant Slack + every operator channel). Implements
// detect.Alerter (IncidentOpened) structurally.
type PolicyRouter struct {
	Resolve  PolicyResolver     // tenant → escalation policy (nil → Default)
	Channels map[string]Alerter // channel name (slack|pagerduty|teams|discord|webhook) → destination
	Default  Alerter            // fallback when no policy matches (e.g. a TenantRouter); may be nil
}

// IncidentOpened delivers per the tenant's escalation policy, else via Default. Best-effort: a
// failing channel never blocks the others; returns the first error.
func (r PolicyRouter) IncidentOpened(ctx context.Context, inc platform.Incident) error {
	var pol *platform.EscalationPolicy
	if r.Resolve != nil {
		pol = r.Resolve(ctx, inc.TenantID)
	}
	if names, ok := pol.ChannelsFor(inc.Severity); ok {
		var firstErr error
		delivered := false
		for _, name := range names {
			if a := r.Channels[name]; a != nil {
				delivered = true
				if err := a.IncidentOpened(ctx, inc); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		// A policy that names only channels the operator hasn't configured shouldn't silently drop
		// the alert — fall back to Default so the incident is never lost.
		if delivered {
			return firstErr
		}
	}
	if r.Default != nil {
		return r.Default.IncidentOpened(ctx, inc)
	}
	return nil
}
