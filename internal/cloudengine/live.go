package cloudengine

import (
	"fmt"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsafety"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Analyzer is the live AWS analysis surface — the only thing that touches the
// customer's account, and every method is READ-ONLY (ADR 0002). In production
// these wrap AWS Access/Reachability Analyzer + benign probes; here it is an
// interface so the live validator is fully unit-testable with a mock. Each call
// is gated through a cloudsafety.Guard by LiveValidator, so a misbehaving
// Analyzer still can't mutate or exceed the live-call budget.
type Analyzer interface {
	// Reachable: is `to` actually reachable from `from` over the live network,
	// computed WITHOUT sending traffic (rung 3, passive reachability)?
	Reachable(from, to string) (bool, error)
	// PermActive: does `principal` actually currently hold the permission for
	// this move right now (rung 2, iam:SimulatePrincipalPolicy)?
	PermActive(principal, action string) (bool, error)
	// Probe: a benign active probe of an edge whose grant is conditioned — does
	// the move actually work, without using the access (rung 4)?
	Probe(from, to string) (bool, error)
}

// the read-only AWS action each rung's analysis maps to (gated by the Guard).
const (
	actReachable  = "ec2:DescribeNetworkInsightsAnalyses" // rung 3
	actPermActive = "iam:SimulatePrincipalPolicy"         // rung 2
	actProbe      = "sts:GetCallerIdentity"               // rung 4 (benign)
)

// LiveValidator climbs the validation ladder for a candidate path using a
// read-only, Guard-gated Analyzer. It implements cloudengine.Validator.
//
// Rungs 2–4 run automatically (bounded by the Guard budget). Rung 5 (active
// exploitation) is NEVER auto-run: a path that can't be confirmed below rung 5
// is recorded in Pending for human approval and reported as not-yet-reachable.
type LiveValidator struct {
	Analyzer Analyzer
	Guard    *cloudsafety.Guard
	MaxRung  int      // ladder cap; 4 = up to benign probe (default). 5 needs a human.
	Pending  []string // paths queued for human-gated rung-5 active validation
}

// NewLiveValidator builds a LiveValidator capped at rung 4 (benign probe).
func NewLiveValidator(a Analyzer, g *cloudsafety.Guard) *LiveValidator {
	return &LiveValidator{Analyzer: a, Guard: g, MaxRung: 4}
}

func (lv *LiveValidator) Validate(p cloudgraph.Path) (bool, int, []types.EvidenceItem) {
	maxRung := lv.MaxRung
	if maxRung <= 0 {
		maxRung = 4
	}
	hyp := pathKey(p)
	var ev []types.EvidenceItem
	rungReached := 1

	for _, e := range p.Edges {
		switch e.Kind {
		case cloudgraph.EdgeNetworkReach:
			ok, item := lv.guarded(actReachable, hyp, 3, fmt.Sprintf("reachable(%s → %s)", e.From, e.To), func() (bool, error) {
				return lv.Analyzer.Reachable(e.From, e.To)
			})
			ev = append(ev, item)
			if !ok {
				return false, max(rungReached, 3), ev
			}
			rungReached = max(rungReached, 3)

		case cloudgraph.EdgeAssumeRole, cloudgraph.EdgeHasAccess, cloudgraph.EdgePrivesc:
			ok, item := lv.guarded(actPermActive, hyp, 2, fmt.Sprintf("perm-active(%s, %s)", e.From, e.Kind), func() (bool, error) {
				return lv.Analyzer.PermActive(e.From, string(e.Kind))
			})
			ev = append(ev, item)
			if !ok {
				return false, max(rungReached, 2), ev
			}
			rungReached = max(rungReached, 2)
			// a conditioned grant needs a benign probe (rung 4) to confirm the
			// condition actually holds at runtime.
			if e.Condition != "" {
				if maxRung < 4 {
					lv.Pending = append(lv.Pending, hyp)
					ev = append(ev, types.EvidenceItem{Query: "rung-5 active validation", Observation: "queued for human approval", AtRung: 5})
					return false, max(rungReached, 4), ev
				}
				ok, item := lv.guarded(actProbe, hyp, 4, fmt.Sprintf("benign-probe(%s → %s)", e.From, e.To), func() (bool, error) {
					return lv.Analyzer.Probe(e.From, e.To)
				})
				ev = append(ev, item)
				if !ok {
					return false, max(rungReached, 4), ev
				}
				rungReached = max(rungReached, 4)
			}

		case cloudgraph.EdgeRunsAs:
			// config fact (instance profile / exec role) — no live check needed.
			ev = append(ev, types.EvidenceItem{Query: fmt.Sprintf("runs-as(%s → %s)", e.From, e.To), Observation: "config fact", AtRung: 0})
		}
	}
	return true, rungReached, ev
}

// guarded runs one Analyzer call through the Guard (enforces read-only + budget)
// and records the evidence item. A Guard rejection (mutating / budget) is
// reported as a failed validation — fail-closed.
func (lv *LiveValidator) guarded(action, hyp string, rung int, query string, call func() (bool, error)) (bool, types.EvidenceItem) {
	item := types.EvidenceItem{Query: query, AtRung: rung}
	if err := lv.Guard.Allow(action, hyp); err != nil {
		item.Observation = "blocked by safety guard: " + err.Error()
		return false, item
	}
	ok, err := call()
	if err != nil {
		item.Observation = "analyzer error: " + err.Error()
		return false, item
	}
	if ok {
		item.Observation = "confirmed"
	} else {
		item.Observation = "not reachable / not active"
	}
	return ok, item
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ Validator = (*LiveValidator)(nil)
var _ = cloudsafety.ReadOnly // keep the safety dep explicit
