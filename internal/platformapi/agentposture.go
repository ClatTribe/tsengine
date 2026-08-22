package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ClatTribe/tsengine/internal/adrsensor"
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

	d.assessAgentEstate(w, r, tenantID, agentposture.Snapshot{Agents: req.Agents}, nil)
}

// handleAgentTelemetry (POST /v1/agents/telemetry) is the LIVE collector path: it accepts Uber ADR
// Sensor's JSONL export directly (Content-Type application/x-ndjson, one AgentEvent per line) and
// maps it to the same snapshot the manual ingest takes.
//
// This is the difference between "we can assess your agent estate if you describe it" and "point the
// sensor at your fleet". ADR Sensor (Apache-2.0, MLSys 2026, production-deployed at Uber) already
// parses Claude Code / Cursor / Cline / Codex / Warp / Claude Desktop logs into one schema, so §13
// holds: we consume the OSS collector's output rather than reimplementing six log parsers.
//
// A malformed line is skipped and REPORTED in the response rather than failing the request — this is
// a fleet export, and one corrupt record from one laptop must not discard every other machine's
// telemetry. The count is returned so an operator can see collection quality instead of silently
// trusting a partial estate.
func (d Deps) handleAgentTelemetry(w http.ResponseWriter, r *http.Request, tenantID string) {
	events, skipped, err := adrsensor.ParseJSONL(http.MaxBytesReader(w, r.Body, 64<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read agent telemetry: "+err.Error()))
		return
	}
	if len(events) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "no parseable ADR AgentEvent records found",
			"reason": "empty_telemetry",
			"hint":   "expected ADR Sensor JSONL (one AgentEvent per line): adr-sensor export --format jsonl",
			// Honest: say how many lines we rejected, so "no agents" is never mistaken for a clean estate.
			"skipped_lines": skipped,
		})
		return
	}
	d.assessAgentEstate(w, r, tenantID, adrsensor.ToSnapshot(events), map[string]any{
		"events": len(events), "skipped_lines": skipped,
	})
}

// assessAgentEstate is the shared assess → enrich → store → incident path for both agent ingests, so
// the manual and collector routes can never drift in how a finding is recorded.
func (d Deps) assessAgentEstate(w http.ResponseWriter, r *http.Request, tenantID string, snap agentposture.Snapshot, extra map[string]any) {
	findings := agentposture.Assess(snap, time.Now().UTC())
	findings = enrichFindings(findings) // L1.5 parity (§11)

	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("agt") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(r.Context(), tenantID, []types.Finding{f})
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("agent posture assessed", "agent_posture",
			map[string]any{"tenant_id": tenantID, "agents": len(snap.Agents), "findings": stored},
			"AI-agent estate ingest")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	body := map[string]any{
		"agents": len(snap.Agents), "issues_detected": stored, "findings": findings,
	}
	// Say what we could not read. Assess skips an agent with no name — a finding that identifies
	// nobody is unactionable — and without this the response would report those agents in the count
	// while silently assessing none of them, which reads as coverage we did not have (§10).
	if notes := ingestNotes(len(snap.Agents), len(snap.Agents)-agentposture.Unnamed(snap),
		"AI agent", "AI agents", "they did not carry an agent name"); len(notes) > 0 {
		body["checks_not_run"] = notes
	}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, http.StatusOK, body)
}
