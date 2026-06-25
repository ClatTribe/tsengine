package operate

import "github.com/ClatTribe/tsengine/internal/shadowit"

// SaaS-app discovery (ADR 0010 Phase 6 wiring): operate already fetches OAuth grants across every
// connected IdP (Google Workspace, M365, Okta). Its checkOAuthGrants flags individual risky apps
// (admin-scope, unverified); this exposes the cross-IdP SaaS-APP INVENTORY + portfolio summary —
// the Nudge/Wing "discover every SaaS the org connected" surface — from that same live data, no
// new connector.
//
// Honesty: operate's grant model carries AdminScope (the app holds a sensitive scope) but NOT
// admin-CONSENT (whether the org sanctioned it), so we mark consent unknown and do NOT assert a
// shadow-IT verdict from data that can't prove it. The inventory + sensitive/unverified/adoption
// signals ARE grounded and ship; the shadow-IT classification lights up once a provider supplies
// consent (M365's consentType — a documented follow-on).

// SaaSInventory builds the SaaS-app inventory + portfolio summary from a workspace's live OAuth
// grants. Deterministic; safe on an empty workspace (zero apps → empty inventory).
func SaaSInventory(ws Workspace) ([]shadowit.App, shadowit.Summary) {
	gs := make([]shadowit.AggregatedGrant, 0, len(ws.OAuthGrants))
	for _, g := range ws.OAuthGrants {
		gs = append(gs, shadowit.AggregatedGrant{
			App:          g.App,
			Scopes:       g.Scopes,
			Users:        g.Users,
			Sensitive:    g.AdminScope, // operate's admin/directory-wide scope = a sensitive grant
			Verified:     g.Verified,
			ConsentKnown: false, // operate doesn't carry admin-consent → inventory only, no shadow-IT verdict
		})
	}
	apps := shadowit.InventoryFromAggregated(gs)
	return apps, shadowit.Summarize(apps)
}
