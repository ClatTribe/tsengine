package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
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
	// The tenant's OWN model (Settings → LLM) takes precedence over the operator-global one (§18.5).
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("cloud investigation needs an LLM (the agent's brain): configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
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
	cc := &cloudagent.Context{
		Snap:    cloudgraph.Ingest(inv),
		Prowler: body.Prowler,
		// G2: feed the cross-surface footholds (a leaked key in code, an exposed host) that correlate
		// INTO this account, so the depth agent verifies paths FROM them first — the code→cloud wedge.
		Bridges: d.tenantCloudBridges(r.Context(), tenantID),
	}
	// llm (pentest.SpecLLM) satisfies cloudengine.LLM structurally — same Generate method.
	rep, ierr := cloudagent.Investigate(r.Context(), llm, cc, cloudagent.Options{MaxIters: 24, MaxHyp: 20})
	if ierr != nil {
		respond(w, nil, ierr)
		return
	}
	// Persist the posted inventory so the AI cloud engineer can later run over STORED cloud state —
	// the prerequisite for the L2 generalist delegating cloud-depth to cloudagent. Best-effort.
	if d.CloudSnapshots != nil {
		_ = d.CloudSnapshots.Put(r.Context(), cloudsnap.Snapshot{
			TenantID: tenantID, Inventory: body.Inventory, Prowler: body.Prowler, CapturedAt: time.Now().UTC(),
		})
	}
	// Build the agent's proven paths into findings, then run them through the SAME L1.5 host-side
	// enrichment chain every other finding gets (§11, enrichFindings) — so the AI Cloud Engineer's OWN
	// findings are first-class (exploitability/confidence + KEV/EPSS on any CVE + MERGED compliance),
	// not the second-class inline-built findings they used to be (the documented §11 follow-on:
	// "Not yet wired: cloudinvestigate.go"). Honors TSENGINE_L15_DISABLED (the ablation).
	built := make([]types.Finding, 0, len(rep.Issues))
	for i, is := range rep.Issues {
		built = append(built, cloudIssueToFinding(d.newID("cloudagent")+"-"+strconv.Itoa(i), is))
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
	// Agent proposes → named vCISO disposes (§18.4): the agent's proven attack paths cluster into
	// candidate risks on the vCISO desk automatically, so the human judges the agent's discoveries.
	risksProposed := 0
	if stored > 0 {
		if seeded, serr := d.seedRisks(r.Context(), tenantID); serr == nil {
			risksProposed = len(seeded)
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("cloud investigated", "cloudagent",
			map[string]any{"tenant_id": tenantID, "paths": stored, "calls": rep.Calls, "risks_proposed": risksProposed}, "AI Cloud Engineer investigation")
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": rep.Summary, "paths_found": stored, "risks_proposed": risksProposed, "calls": rep.Calls, "issues": rep.Issues})
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
		"enabled": d.resolveAgentLLM(r.Context(), tenantID) != nil, // tenant model OR operator-global → runnable
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

// cloudInvestigator returns the L2 generalist's CloudInvestigator (item 3b): it loads the tenant's
// STORED cloud snapshot (#726) and runs the cloud SPECIALIST (cloudagent) over it — the framework's
// altitude split, where the whole-estate generalist delegates cloud-depth on demand. Returns nil when
// no snapshot store is wired, so the investigate_cloud tool isn't exposed (the ≤12-tool cap stays
// clean). The closure degrades gracefully: a missing snapshot / LLM / parse error returns a plain
// message, never an error that aborts the L2 loop.
func (d Deps) cloudInvestigator(tenantID string) func(ctx context.Context, focus string) (string, error) {
	if d.CloudSnapshots == nil {
		return nil
	}
	return func(ctx context.Context, focus string) (string, error) {
		snap, ok, err := d.CloudSnapshots.Get(ctx, tenantID)
		if err != nil || !ok {
			return "No cloud inventory has been ingested for this tenant yet — run a cloud investigation first.", nil
		}
		llm := d.resolveAgentLLM(ctx, tenantID)
		if llm == nil {
			return "Cloud-depth investigation needs an LLM (not configured for this tenant).", nil
		}
		inv, perr := cloudgraph.ParseInventory(snap.Inventory)
		if perr != nil {
			return "The stored cloud inventory could not be parsed.", nil
		}
		cc := &cloudagent.Context{
			Snap: cloudgraph.Ingest(inv), Prowler: snap.Prowler,
			Bridges: d.tenantCloudBridges(ctx, tenantID), // G2: cross-surface footholds (code→cloud wedge)
		}
		// Bounded specialist run (it's a nested agent — keep it tight). pentest.SpecLLM satisfies
		// cloudengine.LLM structurally (same Generate), as the on-demand handler above relies on.
		rep, ierr := cloudagent.Investigate(ctx, llm, cc, cloudagent.Options{MaxIters: 12, MaxHyp: 12})
		if ierr != nil {
			return "Cloud investigation error: " + ierr.Error(), nil
		}
		_ = focus // the specialist explores the whole graph; focus is the generalist's framing hint
		return cloudagent.Render(rep), nil
	}
}
