package crossdetect

import (
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// AnnotatePlatform sets each issue's Platform (the source connector kind: github | aws | gcp |
// gworkspace | okta) by tracing its findings back to the connection they came from:
// Finding.AssetID -> Asset.ConnectionID -> Connection.Kind. Set only when that chain resolves;
// empty otherwise. Labelling / filtering only — never changes ranking or membership.
func AnnotatePlatform(issues []Issue, findings []types.Finding, assets []platform.Asset, conns []platform.Connection) []Issue {
	findingAsset := make(map[string]string, len(findings))
	for _, f := range findings {
		if f.AssetID != "" {
			findingAsset[f.ID] = f.AssetID
		}
	}
	assetConn := make(map[string]string, len(assets))
	for _, a := range assets {
		assetConn[a.ID] = a.ConnectionID
	}
	connKind := make(map[string]string, len(conns))
	for _, c := range conns {
		connKind[c.ID] = c.Kind
	}
	for i := range issues {
		for _, fid := range issues[i].FindingIDs {
			aid, ok := findingAsset[fid]
			if !ok {
				continue
			}
			cid, ok := assetConn[aid]
			if !ok {
				continue
			}
			if kind := connKind[cid]; kind != "" {
				issues[i].Platform = kind
				break
			}
		}
	}
	return issues
}