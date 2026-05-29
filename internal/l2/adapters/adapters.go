// Package adapters wires the L2 catalog's external-service interfaces
// (l2.ThreatIntelLookup / ComplianceLookup / Prober / HTTPDoer) to their real
// implementations. It is the production side of the dependency-injection seam
// that internal/l2 defines: internal/l2 stays pure + mockable (no sandbox, no
// network, no corpus), and this package supplies the concrete backing.
//
// The shape is deliberately NOT strix's: where strix exposes ~10 live-API
// threat-intel tools + raw `terminal`/`python` for depth, tsengine collapses
// each concern into ONE catalog tool backed here by:
//   - the pinned, versioned on-disk corpora the L1.5 hooks already load
//     (reproducible per §10 — never a live NVD/Perplexity call), and
//   - the deterministic /replay handler for depth (§9 — never raw shell).
//
// Construct a fully-wired Deps with NewDeps; pass partial pieces directly to
// l2.Deps if a scan doesn't need every service.
package adapters

import (
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// NewDeps assembles a fully-wired l2.Deps for a live scan: the L1 enriched
// findings the Lead triages, plus real threat-intel/compliance/probe/HTTP
// services. scanID + runsDir + spawner back the Prober's /replay calls.
func NewDeps(target types.Asset, l1 []types.Finding, scanID, runsDir string, spawner replay.Spawner) l2.Deps {
	return l2.Deps{
		Target:      target,
		L1Findings:  l1,
		ThreatIntel: NewThreatIntel(),
		Compliance:  NewCompliance(),
		Prober:      NewProber(scanID, runsDir, spawner),
		HTTP:        NewHTTPDoer(),
	}
}
