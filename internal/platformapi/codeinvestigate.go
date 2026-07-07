package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

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
	if d.Recorder != nil {
		d.Recorder.Record("ai code engineer investigated", "code-agent",
			map[string]any{"tenant_id": tenantID, "repo": body.Repo, "findings": len(body.Findings), "issues": len(rep.Issues), "calls": rep.Calls},
			"AI Code Security Engineer depth investigation")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": rep.Summary, "issues": rep.Issues, "tool_calls": rep.Calls,
		"findings_assessed": len(body.Findings),
	})
}
