package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/codelocalize"
	"github.com/ClatTribe/tsengine/internal/codesweep"
	"github.com/ClatTribe/tsengine/internal/consensus"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleCodeSweep (POST /v1/code/sweep) runs PROACTIVE vulnerability discovery over the connected
// repository: decompose the search into many small questions, answer them in parallel, dispose the
// ungrounded ones, and record what survives.
//
// WHY IT IS DIFFERENT FROM /v1/code/investigate: that endpoint is REACTIVE — it triages findings a
// scanner already reported, so a vulnerability no scanner flagged is invisible to it. This one starts
// from the code. internal/codesweep implements it, was complete and tested, and had NO caller.
//
// GROUNDING (§10) IS THE WHOLE DESIGN HERE, because an LLM proposing vulnerabilities from source is
// exactly the shape that manufactures false confidence:
//
//   - the model PROPOSES; codesweep's disposer refuses anything whose cited location does not exist
//     in the file it was asked about, and the refusals are COUNTED and returned, not swallowed
//   - what that proves is bounded, and the finding says so: the cited line is real and a model argued
//     it is vulnerable. No tool executed anything. So these land as `pattern_match`, the same rung as
//     an unverified scanner regex — never `verified`, which in this codebase means a predicate ran
//   - a capped sweep DECLARES its cap as a coverage finding (asset.CoverageRulePrefix), because a
//     partial sweep reported as a result reads as "we looked at your repository" when we looked at
//     part of it
//
// ON DEMAND, never automatic: it costs a model call per task, so it runs when someone asks.
func (d Deps) handleCodeSweep(w http.ResponseWriter, r *http.Request, tenantID string) {
	llm := d.resolveAgentLLMForRole(r.Context(), tenantID, platform.RoleCode)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, llmRequiredBody("Proactive code sweep"))
		return
	}
	var body struct {
		CWEs     []string `json:"cwes"`      // empty → every class codelocalize can localize
		MaxTasks int      `json:"max_tasks"` // 0 → the package default
		// Panel runs a SECOND OPINION over each surviving candidate before it is recorded: an odd
		// panel of independently-personaed jurors, majority wins, ties keep the finding.
		//
		// This is the one place in the pipeline where a consensus vote may actually DROP something,
		// and it is legitimate precisely because a sweep candidate is not tool-grounded — it is one
		// model's proposal, so a panel disagreeing is a second opinion on an opinion, not an LLM
		// overruling a scanner. Everywhere else an LLM verdict annotates and never suppresses (the
		// Detection Skill triage is annotation-only for exactly this reason).
		//
		// Off by default: it costs jurors × candidates extra model calls.
		Panel bool `json:"panel"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	src, repo := d.codeSourceFor(r.Context(), tenantID)
	if src == nil {
		writeJSON(w, http.StatusBadRequest, errBody(
			"a proactive sweep reads your source, so it needs a connected repository — this is not a "+
				"statement about your code"))
		return
	}
	var files codelocalize.Repo
	for _, p := range src.Files() {
		content, rerr := src.ReadFile(r.Context(), p, 0, 0)
		if rerr != nil || strings.TrimSpace(content) == "" {
			continue
		}
		files = append(files, codelocalize.File{Path: p, Content: content})
	}
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("no readable source files in "+repo+" — nothing to sweep"))
		return
	}

	loc := codelocalize.LLMLocalizer{LLM: llm}
	tasks, perr := codesweep.Plan(r.Context(), loc, files, codesweep.PlanOptions{
		CWEs: body.CWEs, MaxTasks: body.MaxTasks,
	})
	if perr != nil {
		respond(w, nil, perr)
		return
	}
	res, serr := codesweep.Sweep(r.Context(), llm, files, tasks, codesweep.SweepOptions{})
	if serr != nil {
		respond(w, nil, serr)
		return
	}

	dropped := 0
	if body.Panel {
		res.Candidates, dropped = panelReview(r.Context(), llm, res.Candidates)
	}
	findings := sweepFindings(res, repo, time.Now().UTC())
	stored := 0
	if d.Store != nil && len(findings) > 0 {
		_, stored = d.persistDriftFindings(r.Context(), tenantID, findings)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repo":     repo,
		"planned":  res.Planned,
		"ran":      res.Ran,
		"refused":  res.Refused,
		"failed":   res.Failed,
		"coverage": res.Coverage(),
		// Reported, never silent: a panel that quietly halved the results would look like a sweep
		// that found less.
		"panel_dropped": dropped,
		"stored":        stored,
	})
}

// sweepFindings converts surviving candidates, plus the coverage disclosure a capped sweep owes.
func sweepFindings(res codesweep.Result, repo string, now time.Time) []types.Finding {
	var out []types.Finding
	for i, c := range res.Candidates {
		if !c.Vulnerable {
			continue
		}
		out = append(out, types.Finding{
			ID:       fmt.Sprintf("codesweep-%03d", i+1),
			RuleID:   "codesweep::" + strings.ToLower(strings.TrimSpace(c.CWE)),
			Tool:     "codesweep",
			Severity: types.Severity(strings.ToLower(strings.TrimSpace(c.Severity))),
			CWE:      []string{c.CWE},
			Title:    c.Title,
			Endpoint: c.Path,
			// The rung is stated in the text as well as the field, because a reader sees the text.
			Description: c.Rationale + "\n\nProposed by the AI code engineer reading this file, not by " +
				"a scanner: the cited location was confirmed to exist, and nothing was executed to " +
				"prove the weakness is reachable. Treat it as a lead to confirm.",
			// pattern_match, never verified: in this codebase "verified" means a predicate RAN.
			VerificationStatus: types.VerificationPatternMatch,
			DiscoveredAt:       now,
			ToolArgs:           map[string]string{"repo": repo, "evidence": strings.Join(c.Evidence, ", ")},
		})
	}
	// A capped sweep is not an exhaustive one, and the difference is invisible in a result list.
	if res.Planned > res.Ran {
		out = append(out, types.Finding{
			ID:       "codesweep-coverage",
			RuleID:   asset.CoverageRulePrefix + "codesweep-partial",
			Tool:     "codesweep",
			Severity: types.SeverityInfo,
			Title:    "This sweep did not cover the whole repository",
			Endpoint: repo,
			Description: fmt.Sprintf(
				"%d of %d planned questions were asked; the rest were not, so files they would have "+
					"covered were NOT examined. This records an absence of testing, not a weakness.",
				res.Ran, res.Planned),
			VerificationStatus: types.VerificationPatternMatch,
			DiscoveredAt:       now,
		})
	}
	return out
}

// panelReview asks an odd panel of independent jurors whether each surviving candidate is a false
// positive, and keeps the ones the majority believes.
//
// Ties and total juror failure KEEP the candidate — consensus.Validate fails open, and that is the
// right direction here: a deadlocked panel is not evidence of absence.
func panelReview(ctx context.Context, llm interface {
	Generate(context.Context, string) (string, error)
}, cands []codesweep.Candidate) ([]codesweep.Candidate, int) {
	jurors := consensus.DefaultJurors(llm.Generate)
	kept := make([]codesweep.Candidate, 0, len(cands))
	dropped := 0
	for _, c := range cands {
		if !c.Vulnerable {
			continue
		}
		d := consensus.Validate(ctx, types.Finding{
			RuleID: "codesweep::" + c.CWE, Tool: "codesweep", Title: c.Title,
			Description: c.Rationale, Endpoint: c.Path, CWE: []string{c.CWE},
			Severity: types.Severity(strings.ToLower(c.Severity)),
		}, jurors)
		if d.FalsePositive {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped
}
