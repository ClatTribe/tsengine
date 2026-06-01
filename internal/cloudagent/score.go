package cloudagent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AgentScore measures the LLM agent's recorded issues against a set of known real
// targets (the dataset's independent answer key) — the head-to-head metric vs the
// deterministic engine. The agent must reach every real target and invent none.
type AgentScore struct {
	RealTotal   int      `json:"real_total"`
	RealFound   int      `json:"real_found"`
	Recall      float64  `json:"recall"`
	FalseIssues int      `json:"false_issues"` // recorded issues whose target is NOT a real target
	Missed      []string `json:"missed,omitempty"`
	Pass        bool     `json:"pass"`
}

// Score compares the agent's recorded issues to the known real targets. Grounding
// already guarantees every recorded path is real *structurally*; this measures
// whether the agent found the right *targets* and invented none.
func (r *Report) Score(realTargets []string) AgentScore {
	real := map[string]bool{}
	for _, t := range realTargets {
		real[t] = true
	}
	found := map[string]bool{}
	var s AgentScore
	for _, is := range r.Issues {
		if real[is.Target] {
			found[is.Target] = true
		} else {
			s.FalseIssues++
		}
	}
	for t := range real {
		s.RealTotal++
		if found[t] {
			s.RealFound++
		} else {
			s.Missed = append(s.Missed, t)
		}
	}
	sort.Strings(s.Missed)
	if s.RealTotal > 0 {
		s.Recall = float64(s.RealFound) / float64(s.RealTotal)
	} else {
		s.Recall = 1
	}
	s.Pass = s.RealFound == s.RealTotal && s.FalseIssues == 0
	return s
}

// RenderScore formats the agent scorecard.
func RenderScore(s AgentScore) string {
	verdict := "PASS"
	if !s.Pass {
		verdict = "FAIL"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "agent recall: %.2f%% (%d/%d real targets)  |  invented issues: %d  |  verdict: %s\n",
		s.Recall*100, s.RealFound, s.RealTotal, s.FalseIssues, verdict)
	if len(s.Missed) > 0 {
		fmt.Fprintf(&b, "  missed: %s\n", strings.Join(s.Missed, ", "))
	}
	return b.String()
}

// ExportRemediations writes each issue's verified fix to <dir>/<issue-id>.<ext> —
// the "act" output (applyable artifacts on disk). No GitHub/Jira integration, no
// HITL: it emits the reviewed-and-ready artifact for an operator/pipeline to apply.
func ExportRemediations(r *Report, dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, err
	}
	n := 0
	for _, is := range r.Issues {
		if is.FixContent == "" {
			continue
		}
		ext := "txt"
		switch is.FixKind {
		case "aws_scp", "iam_policy":
			ext = "json"
		case "aws_cli":
			ext = "sh"
		}
		path := filepath.Join(dir, is.ID+"."+ext)
		if err := os.WriteFile(path, []byte(is.FixContent+"\n"), 0o600); err != nil {
			return n, fmt.Errorf("export %s: %w", is.ID, err)
		}
		n++
	}
	return n, nil
}
