package platformapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleAutofix (POST /v1/findings/{id}/autofix) is the AI autofix agent — competitor parity with Snyk
// DeepCode AI Fix / Aikido autofix / Copilot Autofix, the highest-value REPOSITORY-asset gap (a founder's
// #1 asset is their codebase, and only cloud/web had a dedicated L2 agent). For a code finding it asks the
// LLM to produce the concrete fix — corrected code + a one-line why — GROUNDED in the finding (rule, CWE,
// file:line, evidence). The deterministic remediate/prbot path already opens the PR + gates the merge;
// this adds the actual patch the human reviews. Gated on an LLM (tenant's own model else operator-global);
// no LLM → 400. Grounded (§10): the prompt cites the real finding; the model never invents a vuln.
func (d Deps) handleAutofix(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("AI autofix needs an LLM: configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	var f *types.Finding
	for i := range findings {
		if findings[i].ID == id {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		writeJSON(w, http.StatusNotFound, errBody("no finding with id "+id))
		return
	}
	fix, gerr := llm.Generate(r.Context(), buildAutofixPrompt(*f))
	if gerr != nil {
		respond(w, nil, gerr)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("autofix drafted", "l2-autofix",
			map[string]any{"tenant_id": tenantID, "finding_id": id, "rule": f.RuleID}, "AI autofix patch")
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding_id": id, "title": f.Title, "rule_id": f.RuleID, "fix": fix})
}

// buildAutofixPrompt builds a grounded autofix prompt from a finding's real details. Pure + testable.
func buildAutofixPrompt(f types.Finding) string {
	var b strings.Builder
	b.WriteString(`You are a senior application-security engineer writing a fix for ONE finding. Produce the
concrete correction, not advice. Ground every change in the finding below — do NOT invent unrelated
issues or guess at code you can't see; if the exact code isn't shown, give the precise, minimal pattern
to apply at the location.

Output Markdown:
1. One sentence: the root cause.
2. A fenced code block with the corrected code (or the exact before→after pattern).
3. One line: how to verify the fix.

FINDING
`)
	fmt.Fprintf(&b, "- rule: %s (tool: %s)\n", nz(f.RuleID, "—"), nz(f.Tool, "—"))
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- weakness: %s\n", strings.Join(f.CWE, ", "))
	}
	fmt.Fprintf(&b, "- severity: %s\n", f.Severity)
	if f.Endpoint != "" {
		fmt.Fprintf(&b, "- location: %s\n", f.Endpoint) // file:line for SAST, URL for DAST
	}
	if f.Title != "" {
		fmt.Fprintf(&b, "- title: %s\n", f.Title)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "- detail: %s\n", truncate(f.Description, 800))
	}
	if len(f.RawOutput) > 0 {
		fmt.Fprintf(&b, "- evidence: %s\n", truncate(string(f.RawOutput), 600))
	}
	return b.String()
}
