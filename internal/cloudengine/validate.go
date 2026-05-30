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
		// Passive reachability can confirm an unconditioned edge, but it CANNOT
		// confirm an edge gated by a runtime condition (MFA/IP/tag) — that needs
		// a live probe (rung 4). So a conditioned (or explicitly-blocked) edge is
		// config-possible but NOT passively reachable: the honest rung-3 verdict
		// is "unknown → not confirmed" (the config-possible ≠ exploitable gap,
		// ADR 0002). This is what stops a config-bad-but-conditioned decoy from
		// being reported as a real path without live validation.
		unconfirmable := o.Blocked[k] || e.Condition != ""
		obs := "reachable"
		if o.Blocked[k] {
			obs = "blocked by runtime condition"
		} else if e.Condition != "" {
			obs = "gated by a runtime condition — needs live validation (rung 4)"
		}
		ev = append(ev, types.EvidenceItem{
			Query:       fmt.Sprintf("reachability(%s → %s, %s)", e.From, e.To, e.Kind),
			Observation: obs,
			AtRung:      3,
		})
		if unconfirmable {
			return false, 3, ev // config-possible but not passively confirmable
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
