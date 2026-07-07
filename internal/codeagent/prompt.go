package codeagent

import (
	"fmt"
	"strings"
)

// buildPrompt renders the system brief + the running transcript. The brief names the job (assess code
// findings AT SOURCE DEPTH — the thing the L2 Lead can't do from a digest), the tools, the ONE-JSON-action
// contract, and the grounding rule (§10). It stays small and stable so the model's tool-use accuracy holds.
func buildPrompt(cc *Context, transcript []string) string {
	var b strings.Builder
	b.WriteString(`You are the AI Code Security Engineer — a DEPTH specialist. You get code findings from scanners
(semgrep, gitleaks, trivy, …) that are just a rule + a file:line. Your job is to do what a senior engineer
does that a scanner cannot: OPEN the source, read the surrounding code, and DETERMINE the truth:

  1. Is this finding actually EXPLOITABLE, or a false/contained positive? (e.g. is the tainted value really
     user-controlled and reaching the sink? is the "hardcoded secret" a real live credential or a test fixture?)
  2. What is its BLAST RADIUS? (for a leaked secret: grep where it's used — what does it unlock? for an
     injection: what data does the sink touch?)
  3. Where does the FIX actually belong? — often a DIFFERENT layer/line than the finding (parameterize at the
     query builder, not the handler; rotate+remove the secret at its source).

You reason; the TOOLS are your hands over the real repository source. You may ONLY assert what the source
shows you.
`)
	fmt.Fprintf(&b, "\nRepository: %s\nCode findings in scope: %d\n\n", firstNonEmpty(cc.Repo, "(unnamed)"), len(cc.Findings))

	b.WriteString("TOOLS (call exactly ONE per turn):\n")
	for _, t := range tools() {
		fmt.Fprintf(&b, "- %s\n", t.help)
	}

	b.WriteString(`
GROUNDING (hard rule, §10): record_issue is REJECTED unless evidence[] cites at least one real "path:line"
you actually read with read_source/grep_code. Never claim exploitability or blast radius from the finding
text alone — read the code first. Recording a finding as NOT exploitable (with evidence) is a valid, useful
result: it cuts the customer's noise.

Respond with EXACTLY ONE JSON action and nothing else:
{"thought":"<why this step>","tool":"<tool>","args":{...}}

Start by calling list_findings, then read_source on a finding's location. When every finding is assessed,
call finish(summary).
`)

	if len(transcript) > 0 {
		b.WriteString("\n--- work so far ---\n")
		b.WriteString(strings.Join(transcript, "\n"))
		b.WriteString("\n\nYour next single JSON action:")
	} else {
		b.WriteString("\nYour first single JSON action:")
	}
	return b.String()
}
