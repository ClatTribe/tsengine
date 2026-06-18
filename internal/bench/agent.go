package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// L2 agent benchmark — the FIRST benchmark of tsengine's *agentic* capability,
// as opposed to L1 detection. The L1 benches measure deterministic scanner
// recall; this measures what the LLM Lead autonomously achieves on a target:
//
//   - detection_rate  — did it FIND the planted objectives?
//   - verified_rate   — did it VERIFY them with evidence (a working PoC /
//     re-fired confirmation)? This is the bar the agentic-offensive leaders
//     publish: XBOW reached HackerOne US #1 with PoC-validated reports, strix
//     validates with working PoCs, NodeZero proves attack paths (GOAD). The
//     bar is VERIFIED findings, not pattern matches (CLAUDE.md §10 grounding).
//   - completion_rate — is the finding evidence-grounded (≥ corroborated), i.e.
//     actionable for the developer audience (§2.2)?
//   - false positives — a decoy must NOT be flagged (the XBOW "no false
//     positives" standard).
//
// Scoring is SUT-agnostic (the §14.2.1 guard scans this file): ground truth
// lives in the objectives fixture DATA, never in this CODE.

// agentCompetitors is the mandatory competitor cite (§14.2.2) for the agentic
// bench: the offensive-AI leaders that publish exploitation-verified results.
var agentCompetitors = Competitors{
	Leaderboard: "agentic-offensive leaders, exploitation-verified: XBOW (HackerOne US #1), strix (OSS), Horizon3 NodeZero (GOAD)",
	Scores: map[string]string{
		"XBOW":     "PoC-validated, ~0 FP",
		"strix":    "PoC-validated multi-agent",
		"NodeZero": "attack-path proven",
	},
	Note: "Agentic bar is VERIFIED findings (a working PoC / evidence-grounded), not pattern matches (CLAUDE.md §10). " +
		"Target: detection_rate at OSS parity AND a competitive verified_rate, with HITL gating on any action.",
}

// agentCategory maps a finding CWE to the vuln class an objective can name.
// Self-contained (kept free of corpus identifiers so this file passes the
// §14.2.1 SUT-agnostic guard).
var agentCategory = map[string]string{
	"CWE-89":  "sqli",
	"CWE-79":  "xss",
	"CWE-22":  "pathtraver",
	"CWE-98":  "pathtraver",
	"CWE-601": "redirect",
	"CWE-78":  "cmdi",
	"CWE-918": "ssrf",
	"CWE-639": "idor",
	"CWE-284": "idor",
	"CWE-352": "csrf",
	"CWE-94":  "rce",
	"CWE-502": "rce",
}

// AgentObjective is one ground-truth item the L2 agent is expected to handle.
// Match precedence: RuleID if set, else Category (via CWE); Endpoint, if set,
// must be a substring of the finding's endpoint.
type AgentObjective struct {
	ID         string `json:"id"`
	Category   string `json:"category,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	MustVerify bool   `json:"must_verify,omitempty"`
}

// AgentObjectives is the agentic-bench fixture: planted ground truth + decoys.
type AgentObjectives struct {
	Target      string           `json:"target"`
	Objectives  []AgentObjective `json:"objectives"`
	Decoys      []AgentObjective `json:"decoys,omitempty"`
	Competitors Competitors      `json:"competitors,omitempty"`
}

// LoadAgentObjectives reads an objectives fixture JSON.
func LoadAgentObjectives(path string) (*AgentObjectives, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided fixture path
	if err != nil {
		return nil, fmt.Errorf("agent bench: open objectives %s: %w", path, err)
	}
	var o AgentObjectives
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("agent bench: parse %s: %w", path, err)
	}
	if len(o.Objectives) == 0 {
		return nil, fmt.Errorf("agent bench: %s has no objectives", path)
	}
	return &o, nil
}

// AgentScore is the agentic outcome over the objective set.
type AgentScore struct {
	Total           int      `json:"total"`
	Found           int      `json:"found"`
	Verified        int      `json:"verified"`
	Completed       int      `json:"completed"`
	MustVerifyTotal int      `json:"must_verify_total"`
	MustVerifyMet   int      `json:"must_verify_met"`
	FalsePositives  int      `json:"false_positives"`
	DetectionRate   float64  `json:"detection_rate"`
	VerifiedRate    float64  `json:"verified_rate"`
	CompletionRate  float64  `json:"completion_rate"`
	Missed          []string `json:"missed,omitempty"`
	UnverifiedMust  []string `json:"unverified_must_verify,omitempty"`
	FlaggedDecoys   []string `json:"flagged_decoys,omitempty"`
}

// AgentReport wraps the score with the competitor cite + the pass gate.
type AgentReport struct {
	Target      string      `json:"target"`
	Score       AgentScore  `json:"score"`
	Pass        bool        `json:"pass"`
	Reason      string      `json:"reason"`
	Competitors Competitors `json:"competitors"`
}

// categoryOf derives a vuln class for a finding from its CWE list.
func categoryOf(f types.Finding) string {
	for _, c := range f.CWE {
		if cat, ok := agentCategory[strings.ToUpper(strings.TrimSpace(c))]; ok {
			return cat
		}
	}
	return ""
}

// matches reports whether a finding satisfies an objective.
func (o AgentObjective) matches(f types.Finding) bool {
	switch {
	case o.RuleID != "":
		if f.RuleID != o.RuleID {
			return false
		}
	case o.Category != "":
		if categoryOf(f) != strings.ToLower(o.Category) {
			return false
		}
	}
	if o.Endpoint != "" && !strings.Contains(f.Endpoint, o.Endpoint) {
		return false
	}
	return true
}

// ScoreAgent grades an L2 agent's run against the objective set. It reads the
// enriched findings (the L2/developer view that carries the L2.5
// verification_status the agentic bar measures), falling back to raw.
func ScoreAgent(obj *AgentObjectives, scan *types.Scan) *AgentReport {
	findings := scan.FindingsEnriched
	if len(findings) == 0 {
		findings = scan.FindingsRaw
	}

	s := AgentScore{Total: len(obj.Objectives)}
	for _, o := range obj.Objectives {
		if o.MustVerify {
			s.MustVerifyTotal++
		}
		var hit *types.Finding
		for i := range findings {
			if o.matches(findings[i]) {
				hit = &findings[i]
				break
			}
		}
		if hit == nil {
			s.Missed = append(s.Missed, o.ID)
			continue
		}
		s.Found++
		verified := hit.VerificationStatus == types.VerificationVerified
		grounded := verified || hit.VerificationStatus == types.VerificationCorroborated
		if verified {
			s.Verified++
		}
		if grounded {
			s.Completed++ // evidence-grounded → actionable for the developer audience (§2.2)
		}
		if o.MustVerify {
			if verified {
				s.MustVerifyMet++
			} else {
				s.UnverifiedMust = append(s.UnverifiedMust, o.ID)
			}
		}
	}

	// FP control: a flagged decoy is a false positive (the XBOW no-FP bar).
	for _, d := range obj.Decoys {
		for i := range findings {
			if d.matches(findings[i]) {
				s.FalsePositives++
				s.FlaggedDecoys = append(s.FlaggedDecoys, d.ID)
				break
			}
		}
	}

	if s.Total > 0 {
		s.DetectionRate = float64(s.Found) / float64(s.Total)
		s.VerifiedRate = float64(s.Verified) / float64(s.Total)
		s.CompletionRate = float64(s.Completed) / float64(s.Total)
	}
	sort.Strings(s.Missed)
	sort.Strings(s.UnverifiedMust)
	sort.Strings(s.FlaggedDecoys)

	rep := &AgentReport{Target: obj.Target, Score: s, Competitors: obj.competitorsOrDefault()}
	rep.Pass, rep.Reason = agentGate(s)
	return rep
}

func (o *AgentObjectives) competitorsOrDefault() Competitors {
	if o.Competitors.Leaderboard != "" || o.Competitors.Note != "" {
		return o.Competitors
	}
	return agentCompetitors
}

// agentGate is the best-in-class bar: find every objective, verify every
// must-verify one, flag zero decoys (the XBOW no-false-positive standard).
func agentGate(s AgentScore) (bool, string) {
	if s.Found < s.Total {
		return false, fmt.Sprintf("missed %d/%d objectives", s.Total-s.Found, s.Total)
	}
	if s.MustVerifyMet < s.MustVerifyTotal {
		return false, fmt.Sprintf("%d/%d must-verify objectives lack a verified PoC", s.MustVerifyTotal-s.MustVerifyMet, s.MustVerifyTotal)
	}
	if s.FalsePositives > 0 {
		return false, fmt.Sprintf("%d false positive(s) — flagged a decoy", s.FalsePositives)
	}
	return true, "all objectives found; every must-verify objective PoC-verified; zero false positives"
}

// RenderAgent prints the human report, always citing competitors (§14.2.2).
func RenderAgent(rep *AgentReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "L2 AGENT BENCHMARK — %s\n", rep.Target)
	s := rep.Score
	fmt.Fprintf(&b, "  detection_rate:   %.0f%% (%d/%d objectives found)\n", s.DetectionRate*100, s.Found, s.Total)
	fmt.Fprintf(&b, "  verified_rate:    %.0f%% (%d/%d PoC-verified)\n", s.VerifiedRate*100, s.Verified, s.Total)
	fmt.Fprintf(&b, "  completion_rate:  %.0f%% (%d/%d evidence-grounded)\n", s.CompletionRate*100, s.Completed, s.Total)
	if s.MustVerifyTotal > 0 {
		fmt.Fprintf(&b, "  must-verify:      %d/%d met\n", s.MustVerifyMet, s.MustVerifyTotal)
	}
	fmt.Fprintf(&b, "  false_positives:  %d\n", s.FalsePositives)
	if len(s.Missed) > 0 {
		fmt.Fprintf(&b, "  missed:           %s\n", strings.Join(s.Missed, ", "))
	}
	status := "FAIL"
	if rep.Pass {
		status = "PASS"
	}
	fmt.Fprintf(&b, "  gate:             %s — %s\n", status, rep.Reason)
	b.WriteString(renderCompetitors(rep.Competitors))
	return b.String()
}
