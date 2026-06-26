package crossdetect

import (
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// BlastRadiusByFinding maps each finding id to its impact-sizing signal (platform.BlastRadius) — "how big
// can this get?" answered from the SAME cross-surface attack chains as /attack-paths (grounded §10/§13: it
// reuses correlate, adds no new detection). A finding that sits on a chain whose terminal step is a crown
// jewel (e.g. a leaked key in a web app that bridges, via a real shared entity, to cloud admin) has a blast
// radius far beyond its own severity — the difference between "a medium finding" and "a medium that gets an
// attacker to your cloud root". Only findings on a crown-jewel chain get a radius; everything else is absent
// (impact = its own severity, never inflated). When a finding is on multiple crown-jewel chains, the CLOSEST
// (fewest hops) wins — the worst case.
func BlastRadiusByFinding(assets []platform.Asset, findings []types.Finding) map[string]platform.BlastRadius {
	out := map[string]platform.BlastRadius{}
	for _, ch := range Correlate(assets, findings) {
		if len(ch.Steps) == 0 {
			continue
		}
		last := ch.Steps[len(ch.Steps)-1]
		if !last.CrownJewel {
			continue // only a chain that actually reaches a crown jewel sizes up the impact
		}
		for i, s := range ch.Steps {
			if s.FindingID == "" {
				continue
			}
			hops := len(ch.Steps) - 1 - i
			br := platform.BlastRadius{ReachesCrownJewel: true, CrownJewelType: last.AssetType, Hops: hops}
			if ex, ok := out[s.FindingID]; !ok || hops < ex.Hops {
				out[s.FindingID] = br // keep the worst (closest) reach
			}
		}
	}
	return out
}
