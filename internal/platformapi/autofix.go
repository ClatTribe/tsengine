package platformapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codeagent"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"

	"github.com/ClatTribe/tsengine/pkg/platform"
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
	llm := d.resolveAgentLLMForRole(r.Context(), tenantID, platform.RoleCode)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, llmRequiredBody("AI autofix"))
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
	// Prefer the BENCHMARKED engine. codeagent.ProposePatch is what tsbench cvepatch grades
	// (execution-verified: the exploit must stop working and the regression must still pass), so when
	// source is reachable the customer gets the implementation the number actually describes.
	if patch, repo, sources, ok := d.autofixViaCodeagent(r.Context(), tenantID, *f, llm); ok {
		// THE TEST TRAVELS WITH THE FIX. A fix without one silently regresses the next time somebody
		// refactors the sanitizer. Best-effort by design: a failure here must never cost the customer the
		// patch, and the generator DROPS a proposal it cannot ground rather than shipping a test that
		// passes trivially — which would be worse than none, since it goes green forever and claims the
		// vulnerability is covered.
		reg, regErr := codeagent.ProposeRegressionTest(r.Context(), llm, codeagent.Finding{
			Class:    strings.ToLower(strings.Join(f.CWE, " ")),
			Endpoint: f.Endpoint,
			Detail:   nz(f.Description, f.Title),
		}, patch, sources)
		_ = regErr // a missing test is a smaller problem than a missing fix
		if d.Recorder != nil {
			d.Recorder.Record("autofix drafted (codeagent)", "l2-autofix",
				map[string]any{"tenant_id": tenantID, "finding_id": id, "rule": f.RuleID, "repo": repo,
					"files": len(patch.Files)}, "AI autofix patch via the benchmarked engine")
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"finding_id": id, "title": f.Title, "rule_id": f.RuleID,
			"fix": patch.Raw, "files": patch.Files, "repo": repo,
			// The DIFF is what a reviewer reads; whole-file contents are what gets applied.
			"diff":   patch.UnifiedDiff(map[string]string{}),
			"engine": "codeagent.ProposePatch (execution-verified in tsbench cvepatch)",
			// Present only when a test survived the grounding gate. Absent means none was produced —
			// stated as absence rather than an empty string, so a caller cannot render "" as a test.
			"regression_test":      regressionPayload(reg),
			"regression_test_note": reg.Note,
		})
		return
	}
	// Fallback: no connected repo, or the file could not be read. This path is HONEST but weaker — it
	// is prompt-only and un-benchmarked, so it says so rather than being presented as the same product.
	fix, gerr := llm.Generate(r.Context(), buildAutofixPrompt(*f))
	if gerr != nil {
		respond(w, nil, gerr)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("autofix drafted", "l2-autofix",
			map[string]any{"tenant_id": tenantID, "finding_id": id, "rule": f.RuleID}, "AI autofix patch")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"finding_id": id, "title": f.Title, "rule_id": f.RuleID, "fix": fix,
		"engine": "prompt-only (no connected repo source — advisory, not an applicable patch)",
	})
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

// codeSourceFor builds live source access for a tenant from its GitHub connection, or nil when the
// tenant has no usable one.
//
// It exists so autofix can reach the SAME code path the T4 benchmark measures. Before this, the two
// had silently diverged: tsbench cvepatch grades codeagent.ProposePatch (3/3 execution-verified),
// while the customer-facing /v1/findings/{id}/autofix called llm.Generate with its own prompt and
// never touched codeagent at all. We were benchmarking one implementation and shipping another, so
// the number described nothing a customer could receive — the same two-views-drifted shape as the
// host/sandbox tool-registry bug.
//
// Single-repo for the same reason codeInvestigator is: types.Finding carries no repo attribution, so
// there is no grounded way to route a finding to its own repo. Degrades safely — no connection, no
// source, and the caller falls back rather than guessing.
func (d Deps) codeSourceFor(ctx context.Context, tenantID string) (src codeagent.SourceProvider, repo string) {
	if d.Vault == nil {
		return nil, ""
	}
	conns, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return nil, ""
	}
	for i := range conns {
		c := conns[i]
		if c.Kind != platform.ConnGitHub || c.Account == "" || c.Config["repo"] == "" {
			continue
		}
		token, oerr := d.Vault.Open(c.SecretRef)
		if oerr != nil || token == "" {
			return nil, ""
		}
		return codeagent.NewGitHubSource(c.Account, c.Config["repo"], c.Config["ref"], token),
			c.Account + "/" + c.Config["repo"]
	}
	return nil, ""
}

// autofixViaCodeagent produces a patch through codeagent.ProposePatch — the benchmarked engine.
//
// Returns ok=false when source is unreachable, so the caller can fall back to the prompt-only path
// instead of failing. That fallback is honest but weaker: it is the un-benchmarked implementation,
// and the response says so rather than presenting both as the same product.
func (d Deps) autofixViaCodeagent(ctx context.Context, tenantID string, f types.Finding, llm codeagent.LLM) (patch codeagent.Patch, repo string, sources []codeagent.SourceFile, ok bool) {
	src, repo := d.codeSourceFor(ctx, tenantID)
	if src == nil {
		return codeagent.Patch{}, "", nil, false
	}
	cf := codeagent.Finding{
		Class:    strings.ToLower(strings.Join(f.CWE, " ")),
		Endpoint: f.Endpoint,
		Detail:   nz(f.Description, f.Title),
	}
	// The finding's endpoint is a relative file:line for repo findings — read that file whole, which is
	// the build context ProposePatch rewrites. An unreadable path returns an error rather than empty
	// content, so a wrong repo degrades to the fallback instead of patching a file we never saw (§10).
	path := f.Endpoint
	if i := strings.LastIndex(path, ":"); i > 0 {
		path = path[:i]
	}
	content, rerr := src.ReadFile(ctx, path, 0, 0)
	if rerr != nil || strings.TrimSpace(content) == "" {
		return codeagent.Patch{}, repo, nil, false
	}
	files := []codeagent.SourceFile{{Path: path, Content: content}}
	p, err := codeagent.ProposePatch(ctx, llm, cf, files)
	if err != nil || p.Empty() {
		return codeagent.Patch{}, repo, nil, false
	}
	return p, repo, files, true
}

// regressionPayload renders the proposed test, or nil when none survived the grounding gate.
//
// nil rather than an empty object: a caller that renders a blank test panel teaches the reader that a
// test exists and is trivial, which is the opposite of what happened. Absence must read as absence.
func regressionPayload(r codeagent.RegressionTest) map[string]any {
	if r.Empty() {
		return nil
	}
	return map[string]any{"path": r.File.Path, "content": r.File.Content}
}
