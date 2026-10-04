package detect

import (
	"context"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// routing.go: who an incident is for.
//
// An incident alert that says "critical SQL injection" and nothing else reaches a shared channel where
// everyone assumes someone else owns it. The asset already records who answers for it (Asset.Owner/Team,
// ADR 0028 G1); this carries that onto the incident when it opens, so the alert and every re-page name a
// person — and @mention them in Slack when their member id is on the escalation roster.
//
// Three states, kept apart because they send a reader to different fixes:
//   - the finding names an asset that has an owner → the owner is named;
//   - the finding names an asset with NO owner → the incident says so (AssetID set, Owner empty), because
//     a page with no route to a person is the scoping gap worth surfacing — never filled with the
//     workspace owner, which would name somebody who never agreed to it;
//   - the finding names no asset → nothing is said about ownership at all: "unknown" is not "unowned".

type routingStore interface {
	ListAssets(ctx context.Context, tenantID string) ([]platform.Asset, error)
	GetTenant(ctx context.Context, id string) (platform.Tenant, error)
}

type router struct {
	assets map[string]platform.Asset
	slack  map[string]string // lower-cased email → Slack member id
}

// routing loads what stamping needs, only when some present finding is tied to an asset. Best-effort: a
// read error leaves incidents unrouted, exactly as before, and never blocks one from opening.
func (d *Detector) routing(ctx context.Context, tenantID string, present map[string]types.Finding) router {
	r := router{}
	need := false
	for _, f := range present {
		if f.AssetID != "" {
			need = true
			break
		}
	}
	// Detect keeps a narrow Store; a store that can also read assets and the tenant enables routing.
	rs, ok := d.Store.(routingStore)
	if !need || !ok {
		return r
	}
	if as, err := rs.ListAssets(ctx, tenantID); err == nil {
		r.assets = make(map[string]platform.Asset, len(as))
		for _, a := range as {
			r.assets[a.ID] = a
		}
	}
	if t, err := rs.GetTenant(ctx, tenantID); err == nil {
		r.slack = map[string]string{}
		for _, c := range t.Contacts {
			if e := strings.ToLower(strings.TrimSpace(c.Email)); e != "" && c.SlackID != "" {
				r.slack[e] = c.SlackID
			}
		}
	}
	return r
}

func (r router) stamp(inc *platform.Incident, f types.Finding) {
	if f.AssetID == "" {
		return
	}
	a, ok := r.assets[f.AssetID]
	if !ok {
		return // the asset is gone or unreadable: unknown, not unowned
	}
	inc.AssetID, inc.AssetTarget = a.ID, a.Target
	inc.Owner, inc.Team = strings.TrimSpace(a.Owner), strings.TrimSpace(a.Team)
	if id, ok := r.slack[strings.ToLower(inc.Owner)]; ok {
		inc.OwnerSlackID = id
	}
}
