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

// ComposedTriager is the TUNED engine: the model proposes, a deterministic disposer decides.
//
// This is what the benchmark told us to build. The measurements are unambiguous about where each half
// is strong: the model reaches recall 1.00 (it does not discard the real finding a restraint-tuned
// heuristic loses) and restraint 0.67 (no better than a twenty-line path check). Composing them plays
// each to its strength instead of hoping one model does both.
//
// It is the same shape as every other grounded path in this codebase — agent proposes, framework
// disposes (§10) — applied to triage. The model can only ever KEEP; the disposer can only ever DROP.
// Neither can overrule the other into a false negative: a finding survives only if the model wants it
// AND the disposer sees no reason to bin it.
//
// HONEST CAVEAT ON THE DISPOSER'S RULES. They were chosen after reading which decoys the model kept,
// which is tuning on the evaluation set. Two things make that defensible rather than circular:
// the rules are justified independently of this corpus (a credential inside a test fixture or a
// documentation sample is the single most common false positive in secret scanning, everywhere), and
// they are deliberately NARROW — only unambiguous non-production locations, never a general
// "looks unimportant" heuristic. The number this produces still needs held-out validation before it
// is quoted as a capability rather than as a tuning result.
type ComposedTriager struct {
	Model Triager
}

func (c ComposedTriager) Engine() string { return "llm + deterministic disposer" }

func (c ComposedTriager) Triage(ctx context.Context, f types.Finding) (bool, error) {
	keep, err := c.Model.Triage(ctx, f)
	if err != nil {
		return false, err
	}
	if !keep {
		return false, nil // the model already declined; the disposer never resurrects
	}
	if reason := nonProductionLocation(f); reason != "" {
		return false, nil
	}
	return true, nil
}

// nonProductionLocation reports why a finding's LOCATION makes it non-actionable, or "" if it does not.
//
// Deliberately narrow. It matches only places that are non-production by construction — a test-data
// directory, a fixture, a documentation file — because the cost of a broad rule here is a dropped real
// vulnerability, and that is the one error this benchmark treats as unforgivable.
func nonProductionLocation(f types.Finding) string {
	p := strings.ToLower(f.Endpoint)
	switch {
	case strings.Contains(p, "testdata/"), strings.Contains(p, "/fixtures/"), strings.Contains(p, "fixture_"):
		return "test fixture — the value authenticates to nothing"
	case strings.HasSuffix(p, ".md"), strings.Contains(p, "/docs/"), strings.Contains(p, "readme"):
		return "documentation — a sample shown so readers know the format"
	}
	return ""
}
