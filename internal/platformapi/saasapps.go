package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/nhidentity"
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

// handleNonHumanIdentities is the non-human / AI-agent identity posture (the ACSP "identity-aware
// policy over human, machine, and agentic actions" lens). Over the SAME persisted OAuth-grant
// inventory the SaaS-apps view uses, it classifies each non-human identity (AI agent / automation /
// integration), assigns a least-privilege level, and a risk verdict — surfacing the over-privileged
// AI-agent / unverified delegated access the inventory view doesn't. Pure presentation; no new scan.
func (d Deps) handleNonHumanIdentities(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := d.Store.ListThirdPartyApps(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	gs := make([]nhidentity.Grant, 0, len(raw))
	for _, a := range raw {
		gs = append(gs, nhidentity.Grant{App: a.AppID, Scopes: a.Scopes, Users: a.Users, Admin: a.AdminScope, Verified: a.Verified})
	}
	ids, sum := nhidentity.Classify(gs)
	if ids == nil {
		ids = []nhidentity.Identity{}
	}
	respond(w, map[string]any{"identities": ids, "summary": sum}, nil)
}
