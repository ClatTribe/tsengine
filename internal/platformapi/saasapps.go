package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/shadowit"
)

// handleSaaSApps is the SaaS-app discovery view (ADR 0010 Phase 6 — the Nudge/Wing "discover
// every SaaS the org connected" surface). It enriches the already-persisted third-party OAuth
// app inventory (ReplaceThirdPartyApps, refreshed each operate scan across Google/M365/Okta)
// into a portfolio summary + per-app risk classification. No new scan, no new connector — pure
// presentation over live data. Honest: the providers carry "admin scope" (sensitive) but not
// admin-consent, so no app is labelled shadow-IT here (that lights up once consentType is
// captured — see operate.SaaSInventory). Tenant-scoped.
func (d Deps) handleSaaSApps(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := d.Store.ListThirdPartyApps(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	gs := make([]shadowit.AggregatedGrant, 0, len(raw))
	for _, a := range raw {
		gs = append(gs, shadowit.AggregatedGrant{
			App:          a.AppID,
			Scopes:       a.Scopes,
			Users:        a.Users,
			Sensitive:    a.AdminScope, // a directory/admin scope = a sensitive grant
			Verified:     a.Verified,
			ConsentKnown: false, // no consent data → inventory only, no shadow-IT verdict (honest)
		})
	}
	apps := shadowit.InventoryFromAggregated(gs)
	respond(w, map[string]any{"apps": apps, "summary": shadowit.Summarize(apps)}, nil)
}
