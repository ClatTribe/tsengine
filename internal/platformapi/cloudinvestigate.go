package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// cloudinvestigate.go is the platform surface for the AI Cloud Security Engineer (the CLI
// `cloud-investigate`) — so the open-ended cloud agent is reachable from the product, not only the CLI.
// It runs the LLM agent (Deps.AgentLLM — a cloud key OR a local Ollama) over a posted cloud inventory +
// optional prowler findings, stores each PROVEN attack path as a finding (so it flows through the same
// issues / attack-paths / grc / incident machinery), and serves the result. Honest gating: no LLM →
// 400 with setup guidance, never a fabricated result (§10).

// handleCloudInvestigate (POST /v1/cloud/investigate) runs one investigation.
func (d Deps) handleCloudInvestigate(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.AgentLLM == nil {
		writeJSON(w, http.StatusBadRequest, errBody("cloud investigation needs an LLM (the agent's brain): set LLM_API_KEY (cloud) or LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	var body struct {
		Inventory json.RawMessage `json:"inventory"`
		Prowler   []types.Finding `json:"prowler"`
	}
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err := json.Unmarshal(raw, &body); err != nil || len(body.Inventory) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody(`body must be {"inventory": <cloud inventory JSON>, "prowler": [...optional findings...]}`))
		return
	}
	inv, err := cloudgraph.ParseInventory(body.Inventory)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	cc := &cloudagent.Context{Snap: cloudgraph.Ingest(inv), Prowler: body.Prowler}
	// d.AgentLLM (pentest.SpecLLM) satisfies cloudengine.LLM structurally — same Generate method.
	rep, ierr := cloudagent.Investigate(r.Context(), d.AgentLLM, cc, cloudagent.Options{MaxIters: 24, MaxHyp: 20})
	if ierr != nil {
		respond(w, nil, ierr)
		return
	}
	stored := 0
	saved := make([]types.Finding, 0, len(rep.Issues))
	for i, is := range rep.Issues {
		f := cloudIssueToFinding(d.newID("cloudagent")+"-"+strconv.Itoa(i), is)
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
		d.Recorder.Record("cloud investigated", "cloudagent",
			map[string]any{"tenant_id": tenantID, "paths": stored, "calls": rep.Calls}, "AI Cloud Engineer investigation")
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": rep.Summary, "paths_found": stored, "calls": rep.Calls, "issues": rep.Issues})
}

// handleCloudInvestigationView (GET /v1/cloud/investigate) returns the tenant's stored cloud-agent
// attack-path findings — the "AI Cloud Engineer" results view, read-only.
func (d Deps) handleCloudInvestigationView(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	paths := make([]types.Finding, 0)
	for _, f := range all {
		if f.Tool == "cloudagent" || strings.HasPrefix(f.RuleID, "cloudagent::") {
			paths = append(paths, f)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   len(paths),
		"paths":   paths,
		"enabled": d.AgentLLM != nil, // tells the UX whether a run is possible
	})
}

// cloudIssueToFinding maps an agent-proven attack path to a stored finding (verified — the agent only
// records paths it confirmed via the graph tools, §10).
func cloudIssueToFinding(id string, is cloudagent.Issue) types.Finding {
	sev := types.Severity(strings.ToLower(strings.TrimSpace(is.Severity)))
	if sev == "" {
		sev = types.SeverityHigh
	}
	desc := is.Rationale
	if is.Remediation != "" {
		desc += "\n\nRemediation: " + is.Remediation
	}
	rawOut, _ := json.Marshal(map[string]any{
		"path": is.Path, "evidence": is.Evidence, "fix_kind": is.FixKind, "fix_verified": is.FixVerified, "fix_content": is.FixContent,
	})
	title := is.TargetName
	if title == "" {
		title = is.Target
	}
	return types.Finding{
		ID: id, RuleID: "cloudagent::attack-path", Tool: "cloudagent", Severity: sev,
		Endpoint: is.Target, Title: title + " — reachable attack path", Description: desc,
		VerificationStatus: types.VerificationVerified, RawOutput: rawOut, DiscoveredAt: time.Now().UTC(),
	}
}
