package platformapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/grc"
)

// handleComplianceAdvisor (POST /v1/compliance/{framework}/advisor) is the vCISO ADVISOR agent — the
// strategic, framework-level companion to the per-gap remediation agent. It reasons over the REAL data
// this campaign added — automated coverage (X of Y controls), the open gaps, what's not connected, and the
// control areas we don't automate — to produce a prioritized audit-readiness roadmap and an HONEST verdict
// ("you are NOT compliant yet because …"). Grounded (§10): the prompt carries the real coverage numbers +
// control ids + the unconnected/unautomated areas; the model prioritizes THOSE, and a named human (the
// vCISO / auditor) still owns the call. Gated on an LLM; no LLM → 400. This is the "agent for better
// analysis" answer, wired to never produce a false-compliant read.
func (d Deps) handleComplianceAdvisor(w http.ResponseWriter, r *http.Request, tenantID string) {
	framework := r.PathValue("framework")
	if d.GRC == nil {
		writeJSON(w, http.StatusBadRequest, errBody("compliance is not configured"))
		return
	}
	if !grc.IsFramework(framework) {
		writeJSON(w, http.StatusNotFound, errBody("unknown framework: "+framework))
		return
	}
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("the compliance advisor needs an LLM: configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	rep, err := d.GRC.Report(r.Context(), tenantID, framework)
	if err != nil {
		respond(w, nil, err)
		return
	}
	readiness := d.computeReadiness(r.Context(), tenantID)

	roadmap, gerr := llm.Generate(r.Context(), buildAdvisorPrompt(rep, readiness))
	if gerr != nil {
		respond(w, nil, gerr)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("compliance advisor roadmap drafted", "l2-compliance",
			map[string]any{"tenant_id": tenantID, "framework": framework, "gaps": rep.Coverage.Gaps, "coverage_pct": rep.Coverage.AutomatedCoveragePct}, "compliance advisor roadmap")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"framework": framework, "title": rep.Title,
		"coverage": rep.Coverage, "roadmap": roadmap,
		// The advisor is guidance, not an attestation — reinforce the no-false-compliant rule in the payload.
		"note": "Advisor guidance, grounded in your live posture. It is not a compliance certification — a named auditor attests that.",
	})
}

// buildAdvisorPrompt grounds the advisor in the real coverage + gaps + connect/attest gaps. Pure + testable.
func buildAdvisorPrompt(rep *grc.Report, readiness grc.ReadinessReport) string {
	cov := rep.Coverage
	var b strings.Builder
	fmt.Fprintf(&b, `You are a seasoned vCISO advising a founder on becoming audit-ready for %s. Using ONLY the
grounded posture below, write a short, prioritized roadmap. Be HONEST and never call them "compliant" — an
auditor attests that. Structure:
1. Where they stand — one plain sentence using the real coverage numbers.
2. Top priorities in order — fix the open gaps, connect the missing integrations, then the controls that
   need manual evidence. Be specific and reference the real control ids / areas below.
3. The honest verdict — "you are NOT yet audit-ready because …" naming the biggest blockers.
Do NOT invent controls or findings; ground everything in the data. Output concise Markdown.

POSTURE FOR %s:
- Automated coverage: %d of %d technical controls assessed (%.0f%%); %d open gap(s); %d not yet assessed.
`, rep.Title, rep.Title, cov.AssessedControls, cov.AssessableControls, cov.AutomatedCoveragePct, cov.Gaps, cov.NotAssessed)

	// the open control gaps (capped)
	const cap = 10
	n := 0
	b.WriteString("- Open control gaps: ")
	gapIDs := []string{}
	for _, row := range rep.Rows {
		if row.Gap {
			gapIDs = append(gapIDs, row.ControlID)
		}
	}
	if len(gapIDs) == 0 {
		b.WriteString("none among the assessed controls.\n")
	} else {
		shown := gapIDs
		if len(shown) > cap {
			shown = shown[:cap]
		}
		fmt.Fprintf(&b, "%s%s\n", strings.Join(shown, ", "), more(len(gapIDs), cap))
		n = len(gapIDs)
	}
	_ = n

	// integrations not connected (the asset-integration ask)
	missing := []string{}
	for _, it := range readiness.Integrations {
		if !it.Connected {
			missing = append(missing, it.Label)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(&b, "- Not connected (so unassessed): %s\n", strings.Join(missing, ", "))
	} else {
		b.WriteString("- All automatable integrations connected.\n")
	}

	// control areas we don't automate (must be attested)
	manual := make([]string, 0, len(readiness.ManualAreas))
	for _, m := range readiness.ManualAreas {
		manual = append(manual, m.Label)
	}
	if len(manual) > 0 {
		fmt.Fprintf(&b, "- Not automated — needs manual evidence + auditor attestation: %s\n", strings.Join(manual, ", "))
	}
	return b.String()
}

func more(total, cap int) string {
	if total > cap {
		return fmt.Sprintf(" (+%d more)", total-cap)
	}
	return ""
}
