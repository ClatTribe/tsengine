package bench

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// impactdiscovery.go — the IMPACT-DISCOVERY benchmark. The AI Security Engineer's PRIMARY value is FINDING
// the vulns that create REAL organisational impact (reach a crown jewel — customer/regulated data, admin/
// root, financial — often via a CROSS-SURFACE chain no single scanner sees), and NOT crying wolf on
// low-impact noise. That matters more than fixing. This measures it: given a noisy estate + the grounded
// facts, does the engineer surface the impactful findings (RECALL — never miss the one that matters),
// leave the noise alone (PRECISION — no false alarms), and invent no impact (§10 grounding).
//
// The AI value-add is that the impactful findings REQUIRE judgment to surface: a leaked key in code that
// only matters because it unlocks a cloud PII bucket (a chain), or a "low" finding whose detail reveals
// prod admin. A per-finding-severity approach misses those (low recall); reasoning over the estate finds
// them. Scored BY IMPACT CATEGORY.

// ImpactType is the kind of organisational impact a finding creates.
type ImpactType string

const (
	ImpactDataExposure ImpactType = "data_exposure"        // reaches customer/regulated data
	ImpactPrivEsc      ImpactType = "privilege_escalation" // reaches admin/root
	ImpactLateral      ImpactType = "lateral_movement"     // a cross-surface chain to a crown jewel
	ImpactExternal     ImpactType = "external_exposure"    // an internet-reachable sensitive surface
)

// DiscoveryFinding is one finding in the estate, with its ground-truth impact.
type DiscoveryFinding struct {
	ID       string         `json:"id"`
	Title    string         `json:"title,omitempty"`
	Surface  string         `json:"surface,omitempty"` // code | cloud | identity | saas | web
	Severity types.Severity `json:"severity"`
	// Detail is the evidence the engineer reads to judge real impact (chains, mis-tags). Surfaced in prompts.
	Detail string `json:"detail,omitempty"`

	// Ground truth (the answer key):
	HighImpact bool       `json:"high_impact"`           // does it create real organisational impact
	ImpactType ImpactType `json:"impact_type,omitempty"` // the kind of impact (set iff HighImpact)
	Reaches    string     `json:"reaches,omitempty"`     // the crown jewel it reaches (for the rationale)
}

// DiscoveryScenario is a noisy estate with a few genuinely high-impact findings.
type DiscoveryScenario struct {
	ID       string             `json:"id"`
	Name     string             `json:"name,omitempty"`
	Findings []DiscoveryFinding `json:"findings"`
	// Context are RAW estate facts (IAM role→policy, bucket→sensitivity, network reachability) that are NOT
	// impact statements — the engineer must CORRELATE them with the findings to DISCOVER a chain (e.g. this
	// leaked key → this role → this PII bucket). This is the honest, un-spoon-fed test: the impact is not
	// pre-written in any single finding's detail; it must be derived. Optional (absent → detail-level test).
	Context []string `json:"context,omitempty"`
}

// EngineerDiscovery is what the AI produced: the finding ids it judges create real organisational impact.
type EngineerDiscovery struct {
	HighImpactIDs []string `json:"high_impact_ids"`
}

// DiscoveryScore grades the discovery against ground truth.
type DiscoveryScore struct {
	ScenarioID string   `json:"scenario_id"`
	TP         int      `json:"tp"`                 // flagged AND high-impact (correct discovery)
	FP         int      `json:"fp"`                 // flagged a LOW-impact finding as high (false alarm / crying wolf)
	FN         int      `json:"fn"`                 // missed a real high-impact finding (the worst failure)
	Missed     []string `json:"missed,omitempty"`   // the high-impact ids it failed to surface
	Invented   []string `json:"invented,omitempty"` // flagged an id not in the estate (hallucinated, §10)
	Recall     float64  `json:"recall"`             // TP / (TP + FN) — never miss the impactful vuln
	Precision  float64  `json:"precision"`          // TP / (TP + FP) — don't cry wolf

	// per impact category — which kinds of impact the engineer surfaces well.
	ByType map[ImpactType]*TypeRecall `json:"by_type,omitempty"`
}

// TypeRecall is the found/total for one impact category.
type TypeRecall struct {
	Found int `json:"found"`
	Total int `json:"total"`
}

// Pass is the clean bar for "find the vuln that creates real impact": every real-impact finding surfaced
// (recall 1.0), NO low-impact noise flagged as high (FP 0 — so flag-everything can't game it), and nothing
// invented. A partial run is reported by the numbers.
func (s DiscoveryScore) Pass() bool {
	return s.Recall >= 1.0 && s.FP == 0 && len(s.Invented) == 0
}

// ScoreDiscovery grades an engineer's discovery. Pure + deterministic — the ground truth is the scenario's
// authored HighImpact facts (justified by each finding's Detail, so it's a fair judgment test, §10).
func ScoreDiscovery(sc DiscoveryScenario, d EngineerDiscovery) DiscoveryScore {
	s := DiscoveryScore{ScenarioID: sc.ID, ByType: map[ImpactType]*TypeRecall{}}
	truth := map[string]DiscoveryFinding{}
	for _, f := range sc.Findings {
		truth[f.ID] = f
		if f.HighImpact {
			t := s.ByType[f.ImpactType]
			if t == nil {
				t = &TypeRecall{}
				s.ByType[f.ImpactType] = t
			}
			t.Total++
		}
	}
	flagged := map[string]bool{}
	for _, id := range d.HighImpactIDs {
		if flagged[id] {
			continue // dedupe
		}
		flagged[id] = true
		f, ok := truth[id]
		if !ok {
			s.Invented = append(s.Invented, id)
			continue
		}
		if f.HighImpact {
			s.TP++
			s.ByType[f.ImpactType].Found++
		} else {
			s.FP++
		}
	}
	for _, f := range sc.Findings {
		if f.HighImpact && !flagged[f.ID] {
			s.FN++
			s.Missed = append(s.Missed, f.ID)
		}
	}
	sort.Strings(s.Missed)
	sort.Strings(s.Invented)
	if s.TP+s.FN > 0 {
		s.Recall = float64(s.TP) / float64(s.TP+s.FN)
	} else {
		s.Recall = 1.0 // no high-impact findings to catch
	}
	if s.TP+s.FP > 0 {
		s.Precision = float64(s.TP) / float64(s.TP+s.FP)
	} else {
		s.Precision = 1.0 // flagged nothing (vacuous) — recall carries the verdict
	}
	return s
}

// RenderDiscoveryScore is a one-line human summary.
func RenderDiscoveryScore(s DiscoveryScore) string {
	pass := ""
	if s.Pass() {
		pass = " [PASS]"
	}
	parts := make([]string, 0, len(s.ByType))
	types := make([]string, 0, len(s.ByType))
	for t := range s.ByType {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		tr := s.ByType[ImpactType(t)]
		parts = append(parts, fmt.Sprintf("%s %d/%d", t, tr.Found, tr.Total))
	}
	return fmt.Sprintf("%s: recall %.0f%% (missed %d) · precision %.0f%% (%d false alarms) · invented %d · [%s]%s",
		s.ScenarioID, s.Recall*100, s.FN, s.Precision*100, s.FP, len(s.Invented), strings.Join(parts, " "), pass)
}
