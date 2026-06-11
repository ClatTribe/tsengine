package runner

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// WorkspaceType is the platform asset type for a non-tech identity/email estate (the
// operate layer's input). The tech asset types reuse the engine's vocabulary.
const WorkspaceType = "workspace"

// WorkspaceSource yields the operate.Workspace snapshot for a workspace asset — a live
// IdP/M365 connector in production, a snapshot file or fake in tests/MVP.
type WorkspaceSource interface {
	Workspace(ctx context.Context, a platform.Asset) (operate.Workspace, error)
}

// AppSink persists a tenant's third-party OAuth app inventory for one provider (satisfied
// by the store). Optional: when set, the operate runner refreshes the inventory each scan.
type AppSink interface {
	ReplaceThirdPartyApps(ctx context.Context, tenantID, provider string, apps []platform.ThirdPartyApp) error
}

// OperateRunner is a ScanRunner for workspace assets: it sources the snapshot and runs
// the grounded identity/email posture checks. It produces the same types.Finding the
// engine does, so the rest of the platform (store / grc / hitl / ledger) is unchanged.
type OperateRunner struct {
	Source WorkspaceSource
	Opts   operate.Options
	Apps   AppSink // optional: persist the third-party app inventory from the live grants
}

// Scan runs the operate posture engine over the asset's workspace snapshot, and (when an
// AppSink is wired) refreshes the third-party app inventory from the live OAuth grants.
func (o *OperateRunner) Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error) {
	if o.Source == nil {
		return nil, fmt.Errorf("operate: no workspace source configured")
	}
	ws, err := o.Source.Workspace(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("operate: load workspace for %s: %w", a.Target, err)
	}
	if o.Apps != nil && ws.Provider != "" {
		apps := make([]platform.ThirdPartyApp, 0, len(ws.OAuthGrants))
		for _, g := range ws.OAuthGrants {
			apps = append(apps, platform.ThirdPartyApp{
				TenantID: a.TenantID, Provider: ws.Provider, AppID: g.App, Scopes: g.Scopes,
				Users: g.Users, AdminScope: g.AdminScope, Verified: g.Verified,
			})
		}
		// best-effort: the inventory is a convenience view, never block the scan on it
		_ = o.Apps.ReplaceThirdPartyApps(ctx, a.TenantID, ws.Provider, apps)
	}
	return operate.Assess(ws, o.Opts), nil
}

// MuxRunner routes a scan to the right backend by asset type, so one platform serves
// both audiences: the sandbox engine for tech assets (repository/web/cloud/...) and the
// operate posture engine for workspace assets. This is how the non-tech audience plugs
// onto the same kernel.
type MuxRunner struct {
	Engine    ScanRunner // tech assets (sandbox) — may be nil in operate-only deployments
	Workspace ScanRunner // workspace assets (operate)
}

// Scan dispatches by asset type.
func (m *MuxRunner) Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error) {
	if a.Type == WorkspaceType {
		if m.Workspace == nil {
			return nil, fmt.Errorf("mux: no workspace runner configured")
		}
		return m.Workspace.Scan(ctx, a)
	}
	if m.Engine == nil {
		return nil, fmt.Errorf("mux: no engine runner for asset type %q", a.Type)
	}
	return m.Engine.Scan(ctx, a)
}
