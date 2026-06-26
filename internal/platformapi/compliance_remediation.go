package platformapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/grc"
)

// handleComplianceRemediation (POST /v1/compliance/{framework}/remediation) is the vCISO "how do I close
// this gap?" agent. For a framework's control GAPS it asks the LLM for concrete, prioritized remediation
// steps GROUNDED in the citing findings — the consultant guidance a founder needs to actually become
// audit-ready, which the deterministic compliance report (gap vs met) doesn't give. One bounded LLM call
// over the gap set. Gated on an LLM (the tenant's own model or the operator-global one); no LLM → 400.
// Grounded (§10): the prompt cites the real control IDs + finding titles; the model proposes fixes for
// THOSE, and a named human still owns the decision to apply them.
func (d Deps) handleComplianceRemediation(w http.ResponseWriter, r *http.Request, tenantID string) {
	framework := r.PathValue("framework")
	if d.GRC == nil {
		writeJSON(w, http.StatusBadRequest, errBody("compliance is not configured"))
		return
	}
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("remediation guidance needs an LLM: configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	rep, err := d.GRC.Report(r.Context(), tenantID, framework)
	if err != nil {
		respond(w, nil, err)
		return
	}
	gaps := make([]grc.ReportRow, 0)
	for _, row := range rep.Rows {
		if row.Gap {
			gaps = append(gaps, row)
		}
	}
	if len(gaps) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"framework": framework, "title": rep.Title, "gap_count": 0,
			"plan": "No control gaps for this framework — you're audit-ready here. Keep monitoring.",
		})
		return
	}
	plan, gerr := llm.Generate(r.Context(), buildRemediationPrompt(rep.Title, gaps))
	if gerr != nil {
		respond(w, nil, gerr)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("compliance remediation drafted", "l2-compliance",
			map[string]any{"tenant_id": tenantID, "framework": framework, "gaps": len(gaps)}, "compliance remediation guidance")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"framework": framework, "title": rep.Title, "gap_count": len(gaps), "plan": plan,
	})
}

// buildRemediationPrompt builds a grounded remediation prompt: each control gap + the real findings that
// drove it, capped so the prompt stays bounded. Pure + testable.
func buildRemediationPrompt(title string, gaps []grc.ReportRow) string {
	const cap = 12
	var b strings.Builder
	fmt.Fprintf(&b, `You are a pragmatic vCISO helping a founder become audit-ready for %s. For EACH control
gap below, give 2–4 concrete, prioritized remediation steps a small engineering team can actually do —
reference the cited findings where relevant, name the fix (config change, control, policy), and keep it
plain-English. Do NOT invent findings; ground every step in what's listed. Output Markdown, one section
per control.

CONTROL GAPS (control id — cited by):
`, title)
	for i, g := range gaps {
		if i >= cap {
			fmt.Fprintf(&b, "- … (+%d more gaps)\n", len(gaps)-cap)
			break
		}
		cites := make([]string, 0, len(g.Evidence))
		for _, ev := range g.Evidence {
			t := ev.Title
			if t == "" {
				t = ev.FindingID
			}
			cites = append(cites, fmt.Sprintf("%q [%s]", t, ev.Severity))
		}
		ctx := "no specific finding — this control simply isn't evidenced yet"
		if len(cites) > 0 {
			ctx = strings.Join(cites, ", ")
		}
		fmt.Fprintf(&b, "- %s — %s\n", g.ControlID, ctx)
	}
	return b.String()
}
