package bench

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// KeywordCWEAttributor is the deterministic substrate: the honest best a non-LLM layer can do from a
// finding's text. It exists to establish the floor — a model that cannot beat plain keyword matching
// on security knowledge is not adding knowledge.
//
// It matches on SYMPTOM vocabulary a scanner would plausibly use, never on the class name (the corpus
// deliberately never states the class), and declines rather than guessing when nothing matches — the
// same restraint the LLM arms are scored on, so the comparison is fair.
type KeywordCWEAttributor struct{}

func (KeywordCWEAttributor) Engine() string { return "keyword-substrate" }

// The rule table is CANONICAL CWE VOCABULARY — the terms MITRE uses to name each class — and nothing
// else. That constraint is deliberate and it is what makes the baseline honest: the corpus and the
// matcher have the same author, so a table tuned to the corpus's own sentences would score ~1.00 and
// prove nothing. (It did exactly that on the first attempt.) Keying only on the class's standard name
// is what a real deterministic mapper would have without foreknowledge of any particular finding — so
// where it fires, a model deserves no credit for agreeing; where it declines, the finding described a
// symptom without naming its class, and naming it requires actual knowledge.
func (KeywordCWEAttributor) Attribute(_ context.Context, c CWECase) (string, error) {
	t := strings.ToLower(c.Title + " " + c.Description + " " + c.RuleID)
	has := func(w string) bool { return strings.Contains(t, w) }
	switch {
	case has("sql injection"), has("sqli"):
		return "CWE-89", nil
	case has("cross-site scripting"), has("xss"):
		return "CWE-79", nil
	case has("path traversal"), has("directory traversal"):
		return "CWE-22", nil
	case has("hard-coded"), has("hardcoded"):
		return "CWE-798", nil
	case has("cleartext transmission"), has("cleartext"):
		return "CWE-319", nil
	case has("broken crypto"), has("weak algorithm"), has("broken algorithm"):
		return "CWE-327", nil
	case has("server-side request forgery"), has("ssrf"):
		return "CWE-918", nil
	case has("xml external entity"), has("xxe"):
		return "CWE-611", nil
	case has("missing authentication"):
		return "CWE-306", nil
	case has("information exposure through an error"), has("error message"):
		return "CWE-209", nil
	case has("httponly"):
		return "CWE-1004", nil
	case has("cross-site request forgery"), has("csrf"):
		return "CWE-352", nil
	case has("improper certificate validation"):
		return "CWE-295", nil
	case has("insertion of sensitive information into log"):
		return "CWE-532", nil
	case has("deserialization of untrusted data"):
		return "CWE-502", nil
	case has("os command injection"), has("command injection"):
		return "CWE-78", nil
	}
	return "", nil // decline — no canonical class name present
}

// LLMCWEAttributor asks a model to name the class. The model PROPOSES; this layer DISPOSES (§10):
// a response that names no CWE and no decline is recorded as unparseable rather than scored as a
// reasoning error, so a formatting weakness can never masquerade as a knowledge weakness — the exact
// confound that made the first localization comparison ambiguous.
type LLMCWEAttributor struct {
	LLM   cloudengine.LLM
	Label string
}

func (a LLMCWEAttributor) Engine() string {
	if a.Label != "" {
		return a.Label
	}
	return "llm"
}

func (a LLMCWEAttributor) Attribute(ctx context.Context, c CWECase) (string, error) {
	if a.LLM == nil {
		return "", fmt.Errorf("no model configured")
	}
	out, err := a.LLM.Generate(ctx, cwePrompt(c))
	if err != nil {
		// Transport failure is not a knowledge failure — surface it rather than scoring it.
		return "", err
	}
	cwe, declined, ok := ParseCWE(out)
	if !ok {
		return "unparseable", nil
	}
	if declined {
		return "", nil
	}
	return cwe, nil
}

// cwePrompt states the task, and states the decline option explicitly. Offering the decline matters:
// without it, a model has no way to express "this is not a technical weakness", and the restraint
// measurement would be scoring prompt design rather than judgement.
func cwePrompt(c CWECase) string {
	var b strings.Builder
	b.WriteString("You are triaging a security scanner finding.\n\n")
	b.WriteString("Finding:\n")
	fmt.Fprintf(&b, "  tool:        %s\n", c.Tool)
	fmt.Fprintf(&b, "  rule:        %s\n", c.RuleID)
	fmt.Fprintf(&b, "  title:       %s\n", c.Title)
	fmt.Fprintf(&b, "  description: %s\n\n", c.Description)
	b.WriteString("Name the single CWE weakness class this finding represents.\n")
	b.WriteString("If it is not a technical weakness class (for example a business-policy issue or an ")
	b.WriteString("operational reliability bug), answer exactly: NONE\n\n")
	b.WriteString("Answer with only the CWE identifier (for example: CWE-79) or NONE. No explanation.\n")
	return b.String()
}
