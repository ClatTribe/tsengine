package cloudengine

import (
	"fmt"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// SnapshotOracle validates a candidate path purely over the snapshot — no live
// touch. A path is reachable (rung 3, "passive reachability") unless one of its
// edges is in Blocked (a runtime condition that denies it, e.g. an MFA/IP
// condition that doesn't hold). This is the deterministic floor used for
// synthetic benchmarking and as the safe default before any live validation.
//
// Blocked is keyed "from->to:kind" (matching cloudgraph edge identity). In a
// real assessment a live Validator (rung 2–4 via cloudsafety.Guard) replaces or
// augments this; the synthetic benchmark uses the oracle so the bench is exact.
type SnapshotOracle struct {
	Blocked map[string]bool
}

func (o SnapshotOracle) Validate(p cloudgraph.Path) (bool, int, []types.EvidenceItem) {
	var ev []types.EvidenceItem
	for _, e := range p.Edges {
		k := fmt.Sprintf("%s->%s:%s", e.From, e.To, e.Kind)
		obs := "reachable"
		if o.Blocked[k] {
			obs = "blocked by runtime condition"
		}
		ev = append(ev, types.EvidenceItem{
			Query:       fmt.Sprintf("reachability(%s → %s, %s)", e.From, e.To, e.Kind),
			Observation: obs,
			AtRung:      3,
		})
		if o.Blocked[k] {
			return false, 3, ev // config-possible but not live-reachable → decoy
		}
	}
	return true, 3, ev
}

// ReasonedOnly is a Validator that never touches live state: it accepts every
// config-possible path at rung 1 (reasoned). Useful to see the raw hypothesis
// set before validation prunes the unreachable ones.
type ReasonedOnly struct{}

func (ReasonedOnly) Validate(p cloudgraph.Path) (bool, int, []types.EvidenceItem) {
	return true, 1, []types.EvidenceItem{{
		Query: "reasoned(path exists in snapshot)", Observation: "config-possible", AtRung: 0,
	}}
}
