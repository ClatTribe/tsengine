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
		llm := d.resolveAgentLLMForRole(ctx, tenantID, platform.RoleCode)
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
	llm := d.resolveAgentLLMForRole(r.Context(), tenantID, platform.RoleCode)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, llmRequiredBody("Code investigation"))
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
		built = append(built, codeIssueToFinding(d.newID("codeagent")+"-"+strconv.Itoa(i), body.Repo,
			endpointOfFinding(body.Findings, is.FindingID), is))
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
	if d.Recorder != nil {
		d.Recorder.Record("ai code engineer investigated", "code-agent",
			map[string]any{"tenant_id": tenantID, "repo": body.Repo, "findings": len(body.Findings), "issues": len(rep.Issues), "confirmed": stored, "calls": rep.Calls},
			"AI Code Security Engineer depth investigation")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": rep.Summary, "issues": rep.Issues, "tool_calls": rep.Calls,
		"findings_assessed": len(body.Findings), "confirmed_exploitable": stored,
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
		"enabled":   d.resolveAgentLLMForRole(r.Context(), tenantID, platform.RoleCode) != nil,
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

// endpointOfFinding returns the ASSESSED L1 finding's own endpoint — the deterministic, scanner-
// produced location. It is the finding's IDENTITY (detect.Key = RuleID|Endpoint), so it must not come
// from model prose: if the agent phrases the location differently between runs ("app/db.go:42" vs
// "app/db.go:41" vs "internal/app/db.go:42"), the key changes and two things break silently — the
// incident churns (resolve + reopen, re-paging the on-call for the same vuln), and retest.Verify sees
// the old key ABSENT and reports the fix CONFIRMED while the vulnerability is still there.
func endpointOfFinding(fs []types.Finding, id string) string {
	for _, f := range fs {
		if f.ID == id {
			return f.Endpoint
		}
	}
	return ""
}

// codeIssueToFinding maps a grounded, EXPLOITABLE code assessment into a first-class verified finding — the
// AI Code Engineer's own output, distinct from the raw scanner hit it assessed (it carries the confirmed
// blast radius + the right-layer fix location the scanner couldn't give).
func codeIssueToFinding(id, repo, l1Endpoint string, is codeagent.CodeIssue) types.Finding {
	// Free-text severity from the model: an unrecognised value ranks 0 (below info), so it would sort
	// beneath every note and fall under detect's incident threshold. Same neutral default as empty —
	// never silently escalate an un-graded confirmation to High, but never let it vanish either.
	sev := types.Severity(strings.ToLower(strings.TrimSpace(is.Severity)))
	if !sev.Valid() {
		sev = types.SeverityMedium
	}
	desc := is.Rationale
	if is.BlastRadius != "" {
		desc += "\n\nBlast radius: " + is.BlastRadius
	}
	if is.Fix != "" {
		desc += "\n\nFix (" + firstNonEmpty(is.FixLocation, "see below") + "): " + is.Fix
	}
	// Identity comes from the SCANNER's endpoint, not the model's FixLocation. The model's location
	// is kept as descriptive metadata (it is already in the description and rawOut) — useful to a
	// human, but never load-bearing for dedup or fix-verification. Falls back to the model's text only
	// when the L1 finding carried no endpoint, which is better than an empty key.
	endpoint := l1Endpoint
	if endpoint == "" {
		endpoint = is.FixLocation
	}
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
		// CORROBORATED, not verified. types.VerificationVerified is defined as "independent method(s)
		// ACTIVELY confirmed it (re-fire via tool-replay)", and the L1.5 confidence hook treats it that
		// way — it floors confidence at 0.95 with the comment "actively re-fired (L2.5)".
		//
		// The code agent earns less than that, and saying so costs nothing real. Its grounding
		// (evidenceGrounded) proves it READ the actual source and cited real path:line locations — but
		// EXPLOITABILITY is the model's judgment (argBool), re-confirmed by nothing. Corroborated is
		// exactly what happened and what the tier means: two INDEPENDENT assessments agreeing (the L1
		// scanner's hit + an agent that read the code) with nothing re-fired.
		//
		// The CLOUD agent keeps verified, and the difference is the point: validatePath deterministically
		// re-checks every edge against the inventory, so an evaluator confirms it, not the model.
		VerificationStatus: types.VerificationCorroborated, RawOutput: rawOut, DiscoveredAt: time.Now().UTC(),
	}
}
