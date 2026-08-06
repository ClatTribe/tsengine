package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ClatTribe/tsengine/internal/agentposture"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type agentPostureRequest struct {
	Agents []agentposture.Agent `json:"agents"`
}

// handleAgentPostureIngest is the AI-AGENT ESTATE POSTURE ingest — the shadow-AI blind spot. Employee
// coding agents (Claude Code, Cursor, Codex, Cline) and the MCP servers they load read source and
// credentials with the developer's own access, and until now the engine could not see them at all:
// nhidentity covers delegated SaaS OAuth grants, sspm covers SaaS config, deviceposture covers
// endpoints — none observe the agents themselves.
//
// A collector (or the team) POSTs the agent inventory; agentposture.Assess surfaces grounded posture
// findings (unsanctioned agent, auto-approve with no human gate, unpinned/unverified MCP server,
// credential-path access, destructive tool use, unrecorded model) into the same store, flowing through
// issues/incidents/grc/hitl like any finding. Grounded + LLM-free: a governed estate yields zero.
//
// The intended live source is Uber's ADR Sensor (Apache-2.0, github.com/uber/ADR — MLSys 2026,
// production-deployed), whose unified AgentEvent schema this request shape maps onto. Wrapping that
// collector as a sandbox tool is the documented follow-on; the posted-snapshot path works today with
// no collector, mirroring the OSINT/SaaS/tprm/devices ingests.
//
// The findings are especially load-bearing for compliance: ISO 42001, NIST AI RMF and the EU AI Act
// are largely PROCEDURAL in our crosswalk (attestation, surfaced honestly by the coverage layer).
// Agent-estate posture converts a slice of those from "we attest" into evidence.
func (d Deps) handleAgentPostureIngest(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req agentPostureRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid agent inventory: "+err.Error()))
		return
	}

	findings := agentposture.Assess(agentposture.Snapshot{Agents: req.Agents}, time.Now().UTC())
	findings = enrichFindings(findings) // L1.5 parity (§11)

	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("agt") + "-" + strconv.Itoa(i)
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
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("agent posture assessed", "agent_posture",
			map[string]any{"tenant_id": tenantID, "agents": len(req.Agents), "findings": stored},
			"AI-agent estate ingest")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agents": len(req.Agents), "issues_detected": stored, "findings": findings,
	})
}
