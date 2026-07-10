package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// codeScanTools are the L1 code scanners whose findings the code-depth specialist assesses at source.
var codeScanTools = map[string]bool{
	"semgrep": true, "gitleaks": true, "trufflehog": true, "trivy": true, "grype": true,
	"codeql": true, "bandit": true, "gosec": true, "checkov": true, "govulncheck": true,
}

// codeInvestigator returns the L2 generalist's CodeInvestigator (the code twin of cloudInvestigator): it
// runs the code SPECIALIST (codeagent) over the tenant's code findings + the connected repo's live source
// (GitHubSource). Returns nil — so the investigate_code tool is NOT exposed and the ≤12-tool cap stays
// clean — unless the tenant has a GitHub connection with a configured repo AND a vault to open its token
// (source access is the prerequisite; without it a code-depth tool can't ground anything). The closure
// degrades gracefully: no LLM / no code findings returns a plain message, never an aborting error.
func (d Deps) codeInvestigator(tenantID string) func(ctx context.Context, focus string) (string, error) {
	if d.Vault == nil {
		return nil
	}
	conns, err := d.Store.ListConnections(context.Background(), tenantID)
	if err != nil {
		return nil
	}
	var gh *platform.Connection
	for i := range conns {
		if conns[i].Kind == platform.ConnGitHub {
			gh = &conns[i]
			break
		}
	}
	// Need an owner (the connection Account) + a specific repo (Config["repo"]) to build a live source.
	// Multi-repo is blocked on a data-model change, not a quick follow-on: types.Finding carries no repo
	// attribution (a repo finding's endpoint is a relative file:line), so there's no grounded way to route a
	// finding to its own repo's source. This single-repo gate degrades SAFELY — a wrong-repo path 404s and
	// grounding refuses it (§10, never a false finding). The clean fix is per-finding repo attribution on the
	// engine's repository-asset scan, then a MultiRepoSource; until then a tenant with one configured repo works.
	if gh == nil || gh.Account == "" || gh.Config["repo"] == "" {
		return nil
	}
	owner, repo := gh.Account, gh.Config["repo"]
	return func(ctx context.Context, focus string) (string, error) {
		llm := d.resolveAgentLLM(ctx, tenantID)
		if llm == nil {
			return "Code-depth investigation needs an LLM (not configured for this tenant).", nil
		}
		token, oerr := d.Vault.Open(gh.SecretRef)
		if oerr != nil || token == "" {
			return "Could not open the GitHub credential for source access.", nil
		}
		all, ferr := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
		if ferr != nil {
			return "Could not load findings.", nil
		}
		code := make([]types.Finding, 0, len(all))
		for _, f := range all {
			if codeScanTools[strings.ToLower(f.Tool)] {
				code = append(code, f)
			}
		}
		if len(code) == 0 {
			return "No code findings to assess at source.", nil
		}
		cc := &codeagent.Context{
			Repo:     owner + "/" + repo,
			Findings: code,
			Source:   codeagent.NewGitHubSource(owner, repo, gh.Config["ref"], token),
		}
		rep, ierr := codeagent.Investigate(ctx, llm, cc, codeagent.Options{MaxIters: 14, Ledger: d.Recorder})
		if ierr != nil {
			return "Code investigation error: " + ierr.Error(), nil
		}
		_ = focus // the specialist assesses the code findings; focus is the generalist's framing hint
		return codeagent.Render(rep), nil
	}
}

// codeinvestigate.go is the platform surface for the AI Code Security Engineer — the code-half twin of
// cloudinvestigate.go. It runs the code-depth agent (internal/codeagent) over a set of code findings + the
// relevant repository source, so the specialist can OPEN the source, trace a tainted value to its sink, and
// determine real exploitability + blast radius + the right fix location — the depth the L2 Lead can't reach
// from a finding digest. Honest gating (§10): no LLM → 400 (never a fabricated result); and the agent itself
// refuses to record any assessment it can't ground in source it actually read.
//
// Source is POSTED today (the "works with no extra creds" path — a connector/CI posts the changed files
// alongside the findings); a connector-backed SourceProvider that fetches from the live repo (GitHub
// file-contents) is the documented gated follow-on, implementing the same codeagent.SourceProvider interface.

// handleCodeInvestigate (POST /v1/code/investigate) runs one code-depth investigation.
func (d Deps) handleCodeInvestigate(w http.ResponseWriter, r *http.Request, tenantID string) {
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("code investigation needs an LLM (the agent's brain): configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	var body struct {
		Repo     string            `json:"repo"`
		Findings []types.Finding   `json:"findings"`
		Source   map[string]string `json:"source"` // path → file content (the repo files the findings touch)
	}
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(`body must be {"repo":"name","findings":[...code findings...],"source":{"path":"file content"}}`))
		return
	}
	if len(body.Findings) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("no code findings in scope — post the repository's code findings to investigate"))
		return
	}

	cc := &codeagent.Context{
		Repo:     body.Repo,
		Findings: body.Findings,
		Source:   codeagent.NewMapSource(body.Source), // nil/empty source → the agent honestly reports it can't read code
	}
	rep, ierr := codeagent.Investigate(r.Context(), llm, cc, codeagent.Options{MaxIters: 24, Ledger: d.Recorder})
	if ierr != nil {
		respond(w, nil, ierr)
		return
	}
	// Persist the CONFIRMED-EXPLOITABLE assessments as first-class findings (tool=codeagent, verified —
	// the agent grounded them in source it read), run through the SAME L1.5 enrichment chain as every
	// other finding (§11) so they flow through issues / grc / incidents. The NOT-exploitable assessments
	// are the noise-cut half — kept in the response, never escalated (they're the agent saying "this
	// scanner hit is contained"). This mirrors cloudinvestigate; §10 holds (only grounded issues persist).
	built := make([]types.Finding, 0, len(rep.Issues))
	for i, is := range rep.Issues {
		if !is.Exploitable {
			continue
		}
		// Don't silently escalate an un-graded confirmation to High: fall back to the ASSESSED finding's
		// own severity, so the agent's verdict carries the scanner's severity unless it explicitly re-rated.
		if strings.TrimSpace(is.Severity) == "" {
			is.Severity = string(severityOfFinding(body.Findings, is.FindingID))
		}
		// Carry the ASSESSED scanner finding's CWE forward — it's the same vuln, now confirmed at source —
		// so compliance.map (CWE-keyed, §11) annotates the confirmation and it folds into the compliance
		// posture. Grounded (§10): the CWE comes from the real scanner finding, not invented.
		f := codeIssueToFinding(d.newID("codeagent")+"-"+strconv.Itoa(i), body.Repo, is)
		f.CWE = cweOfFinding(body.Findings, is.FindingID)
		built = append(built, f)
	}
	stored := 0
	saved := make([]types.Finding, 0, len(built))
	for _, f := range enrichFindings(built) {
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	// Agent proposes → named vCISO disposes (§18.4): the confirmed-exploitable code findings cluster into
	// candidate risks on the vCISO desk automatically, so a human judges the agent's confirmations — the
	// same HITL surface the AI Cloud Engineer already feeds. (The code path used to skip this, so its
	// discoveries never reached the risk register.)
	risksProposed := 0
	if stored > 0 {
		if seeded, serr := d.seedRisks(r.Context(), tenantID); serr == nil {
			risksProposed = len(seeded)
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("ai code engineer investigated", "code-agent",
			map[string]any{"tenant_id": tenantID, "repo": body.Repo, "findings": len(body.Findings), "issues": len(rep.Issues), "confirmed": stored, "calls": rep.Calls, "risks_proposed": risksProposed},
			"AI Code Security Engineer depth investigation")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": rep.Summary, "issues": rep.Issues, "tool_calls": rep.Calls,
		"findings_assessed": len(body.Findings), "confirmed_exploitable": stored, "risks_proposed": risksProposed,
	})
}

// handleCodeInvestigationView (GET /v1/code/investigate) returns the tenant's stored, confirmed-exploitable
// code assessments (tool=codeagent) — so the /code-engineer page shows past runs (the analysis survives
// navigation) instead of only the inline result, mirroring the cloud view. `enabled` reports whether a run
// is possible (an LLM is resolvable).
func (d Deps) handleCodeInvestigationView(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	assessed := make([]types.Finding, 0)
	for _, f := range all {
		if f.Tool == "codeagent" || strings.HasPrefix(f.RuleID, "codeagent::") {
			assessed = append(assessed, f)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":     len(assessed),
		"confirmed": assessed,
		"enabled":   d.resolveAgentLLM(r.Context(), tenantID) != nil,
	})
}

// severityOfFinding returns the assessed L1 finding's own severity (the fallback when the agent didn't
// re-rate), else medium — so a confirmed issue carries the scanner's severity, not a blanket High.
func severityOfFinding(fs []types.Finding, id string) types.Severity {
	for _, f := range fs {
		if f.ID == id && f.Severity != "" {
			return f.Severity
		}
	}
	return types.SeverityMedium
}

// cweOfFinding returns the assessed L1 finding's CWE(s) so the confirmed-at-source finding carries them
// forward — the input to compliance.map (§11). Nil when the assessed finding is unknown or CWE-less (a
// secret/config finding legitimately has none); §10 — never invents a CWE.
func cweOfFinding(fs []types.Finding, id string) []string {
	for _, f := range fs {
		if f.ID == id {
			return f.CWE
		}
	}
	return nil
}

// codeIssueToFinding maps a grounded, EXPLOITABLE code assessment into a first-class verified finding — the
// AI Code Engineer's own output, distinct from the raw scanner hit it assessed (it carries the confirmed
// blast radius + the right-layer fix location the scanner couldn't give).
func codeIssueToFinding(id, repo string, is codeagent.CodeIssue) types.Finding {
	sev := types.Severity(strings.ToLower(strings.TrimSpace(is.Severity)))
	if sev == "" {
		sev = types.SeverityMedium // neutral default — never silently escalate an un-graded confirmation to High
	}
	desc := is.Rationale
	if is.BlastRadius != "" {
		desc += "\n\nBlast radius: " + is.BlastRadius
	}
	if is.Fix != "" {
		desc += "\n\nFix (" + firstNonEmpty(is.FixLocation, "see below") + "): " + is.Fix
	}
	endpoint := is.FixLocation
	if endpoint == "" && len(is.Evidence) > 0 {
		endpoint = is.Evidence[0]
	}
	rawOut, _ := json.Marshal(map[string]any{
		"assesses_finding": is.FindingID, "evidence": is.Evidence, "blast_radius": is.BlastRadius,
		"fix_location": is.FixLocation, "fix": is.Fix, "repo": repo,
	})
	title := is.Title
	if title == "" {
		title = "Confirmed exploitable"
	}
	// RuleID incorporates the ASSESSED finding id so two confirmations at the same fix location stay
	// DISTINCT under detect.Key (RuleID|Endpoint) — otherwise the second would mask the first in
	// incidents / unified issues, silently dropping a confirmed-exploitable vuln.
	rule := "codeagent::confirmed-exploitable"
	if is.FindingID != "" {
		rule += "::" + is.FindingID
	}
	return types.Finding{
		ID: id, RuleID: rule, Tool: "codeagent", Severity: sev,
		Endpoint: endpoint, Title: title + " — confirmed at source", Description: desc,
		VerificationStatus: types.VerificationVerified, RawOutput: rawOut, DiscoveredAt: time.Now().UTC(),
	}
}
