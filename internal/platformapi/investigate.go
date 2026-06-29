package platformapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleIssueInvestigate (POST /v1/issues/{key}/investigate) is the per-issue agentic verb of the AI
// Security Engineer — sprinkled onto the Issues surface, not parked in a separate console. For ONE
// unified issue it returns the GROUNDED cross-surface context (the deterministic attack chain it sits on
// + its blast radius — always, no LLM needed) PLUS, when an LLM is configured, a bounded L2 Lead run
// scoped to that issue: root cause, how it chains, and the recommended right-layer fix.
//
// §10 grounding: the chain + blast radius are real (correlate / blastradius, the SAME machinery as
// /attack-paths), and the narrative rests on the issue's L1 findings. Gracefully degrades — no LLM →
// the deterministic half + a "turn on the AI engineer" note (200, never a fabricated narrative). The
// LLM is gated exactly like /v1/l2/translate (own key any plan, operator LLM for AI-entitled plans).
func (d Deps) handleIssueInvestigate(w http.ResponseWriter, r *http.Request, tenantID string) {
	// The issue key is rule_id|endpoint (or a CVE) — it contains '/' and ':' (endpoint URLs, ARNs), so it
	// can't ride in a {key} path segment (%2F breaks Go ServeMux matching → 404). It goes in the body.
	var body struct {
		Key string `json:"key"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	key := body.Key
	if key == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing issue key"))
		return
	}
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	var issue *crossdetect.Issue
	for _, is := range crossdetect.UnifiedIssues(findings) {
		if is.Key == key {
			cp := is
			issue = &cp
			break
		}
	}
	if issue == nil {
		writeJSON(w, http.StatusNotFound, errBody("issue not found"))
		return
	}

	// Scope to this issue's raw findings.
	idset := make(map[string]bool, len(issue.FindingIDs))
	for _, id := range issue.FindingIDs {
		idset[id] = true
	}
	issueFindings := make([]types.Finding, 0, len(idset))
	for _, f := range findings {
		if idset[f.ID] {
			issueFindings = append(issueFindings, f)
		}
	}

	pAssets, _ := d.Store.ListAssets(r.Context(), tenantID)

	// Deterministic, GROUNDED context (always — no LLM): the cross-surface chains this issue sits on +
	// the worst (closest-to-crown-jewel) blast radius across its findings.
	issueChains := chainsForFindings(crossdetect.Correlate(pAssets, findings), idset)
	blast := worstBlast(crossdetect.BlastRadiusByFinding(pAssets, findings), issue.FindingIDs)

	resp := map[string]any{
		"issue":        issue,
		"chains":       renderChains(issueChains),
		"blast_radius": blast,
		"ai_enabled":   false,
	}

	client := d.resolveLeadClient(r.Context(), tenantID)
	if client == nil {
		resp["note"] = "Turn on the AI Security Engineer (Settings → LLM, or an AI-enabled plan) for the root-cause + right-layer fix analysis. The cross-surface chain and blast radius above are computed deterministically."
		writeJSON(w, http.StatusOK, resp)
		return
	}
	out, rerr := d.runInvestigate(r.Context(), tenantID, client, issue, issueFindings, findings)
	if rerr != nil {
		respond(w, nil, rerr)
		return
	}
	resp["ai_enabled"] = true
	resp["summary"] = out.Summary
	reports := out.Findings
	if reports == nil {
		reports = []types.Finding{}
	}
	resp["reports"] = reports
	resp["model"] = out.Model
	resp["iterations"] = out.Iterations
	if d.Recorder != nil {
		d.Recorder.Record("ai engineer investigated issue", "l2-lead",
			map[string]any{"tenant_id": tenantID, "issue": key, "reports": len(reports)},
			"AI Security Engineer per-issue investigation")
	}
	writeJSON(w, http.StatusOK, resp)
}

// runInvestigate runs the L2 Lead SCOPED to one issue (its findings) but with the WHOLE-estate
// cross-surface chains in context, so the dig is focused yet graph-aware. A small budget — a per-issue
// dive, not a full estate translate. Mirrors runTranslate; differs only in the scoped finding set + cap.
func (d Deps) runInvestigate(ctx context.Context, tenantID string, client l2.Client, issue *crossdetect.Issue, issueFindings, allFindings []types.Finding) (l2.Outcome, error) {
	pAssets, _ := d.Store.ListAssets(ctx, tenantID)
	target := types.Asset{Type: types.AssetWebApplication, Target: "tenant:" + tenantID}
	if issue.Endpoint != "" {
		target.Target = issue.Endpoint
	} else if len(pAssets) > 0 {
		target = types.Asset{Type: types.AssetType(pAssets[0].Type), Target: pAssets[0].Target}
	}
	// The Lead sees the WHOLE estate's unified issues + cross-surface chains, so it can explain how THIS
	// issue (the scoped L1Findings) bridges to anything that matters — the "three scanners → one
	// engineer" reasoning. L1Findings is scoped to the issue, so the deliverable focuses on it.
	estate := l2.EstateContext{
		Issues:      toIssueDigests(crossdetect.UnifiedIssues(allFindings)),
		AttackPaths: renderChains(crossdetect.Correlate(pAssets, allFindings)),
	}
	dep := l2.Deps{Target: target, L1Findings: issueFindings}
	dep.CloudInvestigator = d.cloudInvestigator(tenantID)
	budget := l2.DefaultBudget()
	budget.MaxIterations = 8 // a per-issue dive, tighter than the 16-iter whole-estate translate
	agent, err := l2.New(client, l2.BuildCatalog(dep), budget)
	if err != nil {
		return l2.Outcome{}, err
	}
	agent.WithEstate(estate)
	return agent.Run(ctx, target, issueFindings)
}

// chainsForFindings filters the cross-surface chains to those whose steps include one of the issue's
// findings — so we render only the chains THIS issue actually participates in.
func chainsForFindings(chains []correlate.Chain, idset map[string]bool) []correlate.Chain {
	out := make([]correlate.Chain, 0)
	for _, ch := range chains {
		for _, s := range ch.Steps {
			if s.FindingID != "" && idset[s.FindingID] {
				out = append(out, ch)
				break
			}
		}
	}
	return out
}

// worstBlast picks the closest-to-crown-jewel blast radius across the issue's findings (the worst case).
func worstBlast(byFinding map[string]platform.BlastRadius, ids []string) platform.BlastRadius {
	var best platform.BlastRadius
	for _, id := range ids {
		if br, ok := byFinding[id]; ok && (!best.ReachesCrownJewel || br.Hops < best.Hops) {
			best = br
		}
	}
	return best
}
