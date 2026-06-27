package platformapi

import (
	"context"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// planLimits resolves a tenant's plan entitlements, defaulting to Free on any lookup error
// (fail-safe: an unreadable plan never grants paid entitlements or the operator's LLM budget).
func (d Deps) planLimits(ctx context.Context, tenantID string) platform.PlanLimits {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return platform.Entitlements(platform.PlanFree)
	}
	return platform.Entitlements(t.Plan)
}
