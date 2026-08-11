package bench

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// SeverityTriager is the honest deterministic baseline: keep anything high or above.
//
// It is what a queue with no triage layer gives you, and it is the bar any claim of "we triage for
// you" has to clear. Its shape is instructive — near-perfect recall, near-zero restraint — because
// every decoy in the corpus is ALSO high or critical. That is not a rigged corpus; it is what real
// scanner output looks like. A test-fixture credential and a live production key are both reported
// critical, which is precisely why triage is a judgement task and not a threshold.
type SeverityTriager struct{}

func (SeverityTriager) Engine() string { return "severity-threshold" }

func (SeverityTriager) Triage(_ context.Context, f types.Finding) (bool, error) {
	switch strings.ToLower(string(f.Severity)) {
	case "critical", "high":
		return true, nil
	}
	return false, nil
}

// PathHeuristicTriager adds the one deterministic signal that genuinely helps: where the finding
// lives. Test directories, fixtures and documentation are the classic dismissals.
//
// It is included to keep the LLM arm honest. If a model cannot beat a twenty-line path check, the
// intelligence is not earning its cost — and this is the kind of baseline that is easy to omit
// precisely because it makes the headline number look worse.
type PathHeuristicTriager struct{}

func (PathHeuristicTriager) Engine() string { return "severity+path-heuristic" }

func (PathHeuristicTriager) Triage(ctx context.Context, f types.Finding) (bool, error) {
	keep, _ := SeverityTriager{}.Triage(ctx, f)
	if !keep {
		return false, nil
	}
	hay := strings.ToLower(f.Endpoint + " " + f.RuleID)
	for _, marker := range []string{"testdata/", "/test/", "_test.", "fixture", "/docs/", "readme", "example"} {
		if strings.Contains(hay, marker) {
			return false, nil
		}
	}
	return true, nil
}

// LLMTriager asks a model to make the call, with the context a human would use.
//
// The prompt states BOTH failure modes explicitly. Told only "find the real ones", a model keeps
// everything and scores zero on Youden; told only "filter noise", it drops real vulnerabilities. Since
// both an 8B general and an 8B security model measurably over-attribute, naming the cost of each
// error is not prompt decoration — it is the difference between measuring judgement and measuring a
// default bias.
type LLMTriager struct {
	LLM   cloudengine.LLM
	Label string
}

func (t LLMTriager) Engine() string {
	if t.Label != "" {
		return t.Label
	}
	return "llm"
}

func (t LLMTriager) Triage(ctx context.Context, f types.Finding) (bool, error) {
	if t.LLM == nil {
		return false, fmt.Errorf("no model configured")
	}
	out, err := t.LLM.Generate(ctx, triagePrompt(f))
	if err != nil {
		return false, err
	}
	low := strings.ToLower(out)
	// Check DROP first: "this is not actionable" contains "actionable", so testing for the keep token
	// first would read a dismissal as a keep.
	for _, d := range []string{"drop", "not actionable", "noise", "false positive", "dismiss"} {
		if strings.Contains(low, d) {
			return false, nil
		}
	}
	if strings.Contains(low, "actionable") || strings.Contains(low, "keep") {
		return true, nil
	}
	// An unparseable answer must not silently become a decision. Defaulting to KEEP is the safe
	// direction — it costs restraint, never recall, so a formatting failure can never hide a real
	// vulnerability.
	return true, nil
}

func triagePrompt(f types.Finding) string {
	var b strings.Builder
	b.WriteString("You are a senior security engineer triaging one scanner finding.\n\n")
	fmt.Fprintf(&b, "  tool:        %s\n  rule:        %s\n  severity:    %s\n  title:       %s\n",
		f.Tool, f.RuleID, f.Severity, f.Title)
	fmt.Fprintf(&b, "  location:    %s\n  description: %s\n\n", f.Endpoint, f.Description)
	b.WriteString("Decide whether this deserves engineering work.\n\n")
	b.WriteString("Both mistakes are costly, in different ways:\n")
	b.WriteString("  - dismissing a real vulnerability is how a breach happens;\n")
	b.WriteString("  - keeping noise is how an engineer stops trusting the queue and ignores all of it.\n\n")
	b.WriteString("Scanners report test fixtures, vendor documentation samples, unbuilt vendored code and\n")
	b.WriteString("unreachable paths at the same severity as live production issues. Judge the CONTEXT, not\n")
	b.WriteString("the severity label.\n\n")
	b.WriteString("Answer with exactly one word: ACTIONABLE or DROP.\n")
	return b.String()
}
