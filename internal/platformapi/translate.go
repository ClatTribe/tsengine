package platformapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleL2Translate (POST /v1/l2/translate) runs the L2 Lead/translator over the tenant's findings to
// produce the developer/founder-facing CONSULTANT DELIVERABLE — prioritized findings, attack-chain
// narrative, plain-English explanations, remediation. This is the L2 "AI security engineer translates
// for non-security teams" value (§2.2), now reachable from the platform (was CLI/scan-only). The model
// reasons; every recorded report still references the L1 evidence it rests on (§10). Gated on a
// tool-calling LLM (the tenant's own model OR the operator-global one — cloud key or local Ollama); no
// client → 400 with setup guidance, never a fabricated report.
func (d Deps) handleL2Translate(w http.ResponseWriter, r *http.Request, tenantID string) {
	client := d.resolveLeadClient(r.Context(), tenantID)
	if client == nil {
		writeJSON(w, http.StatusBadRequest, errBody("the L2 translator needs a tool-calling LLM: configure one in Settings → LLM, or set ANTHROPIC_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	if len(findings) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"summary": "No findings to translate yet — run a scan first.", "reports": []types.Finding{}})
		return
	}
	out, rerr := d.runTranslate(r.Context(), tenantID, client, findings)
	if rerr != nil {
		respond(w, nil, rerr)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("l2 translated", "l2-lead",
			map[string]any{"tenant_id": tenantID, "reports": len(out.Findings), "iterations": out.Iterations}, "L2 translator deliverable")
	}
	reports := out.Findings
	if reports == nil {
		reports = []types.Finding{}
	}
	// Persist as the tenant's latest whole-estate triage so it survives navigation (best-effort).
	saved := d.persistAIAnalysis(r.Context(), tenantID, "triage", "", "Whole-estate triage", out, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": out.Summary, "reports": reports, "analysis_id": saved.ID, "saved_at": saved.CreatedAt,
		"iterations": out.Iterations, "stop_reason": out.StopReason, "cost_usd": out.CostUSD, "model": out.Model,
	})
}

// resolveLeadClient returns the tool-calling l2.Client for the tenant: its own configured model (the
// per-tenant key opened from the vault — Anthropic/Claude, the OpenAI-compatible family, or Gemini via
// its OpenAI-compatible endpoint) else the operator-global client (d.LeadClient, from l2.ClientFromEnv —
// Anthropic, OpenAI, or a local Ollama). nil when neither is set. A tenant's OWN key is honoured on ANY
// plan (they pay for it); the operator-global client is gated to AI-entitled plans.
func (d Deps) resolveLeadClient(ctx context.Context, tenantID string) l2.Client {
	if provider, model, key, ok := d.ResolveTenantLLM(ctx, tenantID); ok {
		switch strings.ToLower(provider) {
		case "anthropic", "claude":
			return l2.NewAnthropicClientWithKey(model, key) // customer's own Claude key → drives Triage/Investigate
		case "gemini", "google", "googleai":
			// Gemini exposes an OpenAI-compatible surface; route the tenant key there so tool-calling works.
			return l2.NewOpenAICompatClient(model, "https://generativelanguage.googleapis.com/v1beta/openai", key)
		case "openai", "openai-compat", "ollama", "vllm", "openrouter", "lmstudio":
			return l2.NewOpenAICompatClient(model, "", key) // tenant's OWN key → allowed on any plan
		}
	}
	// Operator-global client → only for AI-entitled plans (the economic invariant: a Free tenant
	// without its own key must never spend the operator's LLM budget). Previously ungated — a Free
	// tenant could drive /v1/l2/translate on the operator's dime.
	if d.LeadClient != nil && d.operatorLLMAllowed(ctx, tenantID) {
		return d.LeadClient
	}
	return nil
}

// operatorLLMAllowed reports whether a tenant may drive the OPERATOR-GLOBAL LLM (d.LeadClient / d.AgentLLM).
// Normally this is the economic gate — AI-entitled plans only, so a Free tenant never spends operator budget.
// TSENGINE_DEV_LLM_ALL_PLANS=1 is a DEV-ONLY override (off by default → the production invariant is intact):
// it lets `make dev` + the file-relay proxy power the AI engine for any test tenant without a paid plan or a
// customer key. NEVER set it in production — it would let Free tenants spend the operator's LLM budget.
func (d Deps) operatorLLMAllowed(ctx context.Context, tenantID string) bool {
	if os.Getenv("TSENGINE_DEV_LLM_ALL_PLANS") == "1" {
		return true
	}
	return d.planLimits(ctx, tenantID).AIEnabled
}

// runTranslate is the shared L2 engineer core (used by the on-demand POST /v1/l2/translate AND the
// post-scan auto-review). It builds the L1.7 estate view (deduped/corroborated unified issues +
// cross-surface attack paths — the platform computes crossdetect; l2 stays engine-pure) and runs the
// Lead over it. The caller resolves + validates the client (so the gating policy differs per path).
func (d Deps) runTranslate(ctx context.Context, tenantID string, client l2.Client, findings []types.Finding) (l2.Outcome, error) {
	pAssets, _ := d.Store.ListAssets(ctx, tenantID)
	target := types.Asset{Type: types.AssetWebApplication, Target: "tenant:" + tenantID}
	if len(pAssets) > 0 {
		target = types.Asset{Type: types.AssetType(pAssets[0].Type), Target: pAssets[0].Target}
	}
	// Whole-estate pass: the deliverable scopes to all findings, 16-iter cap.
	return d.runEstateAgent(ctx, tenantID, client, target, findings, findings, 16)
}

// runEstateAgent is the shared L2-Lead core for BOTH the whole-estate translate (l1Findings == allFindings)
// and the per-issue investigate (l1Findings == the issue's findings). It builds the cross-surface estate
// context (deduped unified issues + attack chains over allFindings — the "three scanners → one engineer"
// reasoning) once, scopes the deliverable to l1Findings, wires cloud-depth delegation, and runs the
// bounded agent. One place — was duplicated across runTranslate + runInvestigate.
func (d Deps) runEstateAgent(ctx context.Context, tenantID string, client l2.Client, target types.Asset, l1Findings, allFindings []types.Finding, maxIter int) (l2.Outcome, error) {
	pAssets, _ := d.Store.ListAssets(ctx, tenantID)
	estate := l2.EstateContext{
		Issues:      toIssueDigests(crossdetect.UnifiedIssues(allFindings)),
		AttackPaths: renderChains(crossdetect.Correlate(pAssets, allFindings)),
	}
	dep := l2.Deps{Target: target, L1Findings: l1Findings}
	// Cloud-depth delegation: when a stored cloud snapshot exists, the generalist can call investigate_cloud
	// to run the cloud specialist over it. nil when no snapshot store → tool not exposed.
	dep.CloudInvestigator = d.cloudInvestigator(tenantID)
	// Code-depth delegation: when a GitHub repo is connected, the generalist can call investigate_code to
	// run the code specialist over its live source. nil when no connected repo → tool not exposed (cap-safe).
	dep.CodeInvestigator = d.codeInvestigator(tenantID)
	budget := l2.DefaultBudget()
	budget.MaxIterations = maxIter
	agent, err := l2.New(client, l2.BuildCatalog(dep), budget)
	if err != nil {
		return l2.Outcome{}, err
	}
	agent.WithEstate(estate)
	return agent.Run(ctx, target, l1Findings)
}

// AutoReviewAfterScan is the runner.Service.AfterScan hook: once a scan pass surfaces something NEW,
// the AI Security Engineer reviews the estate automatically (instead of waiting for a human to click).
// Gated so a Free tenant never auto-spends the operator's LLM budget: a tenant's OWN key is allowed on
// any plan, but the operator-global client only drives auto-review for AI-entitled plans. Best-effort —
// errors are logged + swallowed, never affecting the scan.
func (d Deps) AutoReviewAfterScan(ctx context.Context, tenantID string, findings []types.Finding, openedIncidents int) {
	if len(findings) == 0 {
		return
	}
	client := d.resolveLeadClient(ctx, tenantID) // gated: own key (any plan) OR operator LLM (AI-entitled only)
	if client == nil {
		return // no own key + not AI-entitled (or no LLM configured at all) → don't spend operator budget
	}
	// COST bound for continuous operation: run the LLM when something CHANGED (a new incident opened) OR
	// this tenant has never had an analysis yet (the first-connect "aha" — a newly-connected SMB shouldn't
	// need to click Triage to get an initial review). Otherwise skip: a static estate re-scanned every
	// monitor pass must NOT re-spend the LLM. The persisted-analysis store is the "have we reviewed before"
	// signal, so this is bounded to change + first-run, not per-pass.
	if openedIncidents == 0 && d.hasPriorTriage(ctx, tenantID) {
		return
	}
	out, err := d.runTranslate(ctx, tenantID, client, findings)
	if err != nil {
		slog.Warn("[auto-review] AI engineer review failed", "tenant", tenantID, "err", err)
		return
	}
	// Agent proposes → named vCISO disposes (§18.4): the whole-estate review clusters the tenant's high+
	// findings into candidate risks on the vCISO desk — the SAME agent-proposes-risk step the on-demand
	// cloud investigation does (cloudinvestigate.go), which the routine scan→auto-review path was missing.
	// Without this, a normal scan's high+ findings never reached the vCISO desk unless a human manually
	// POSTed /v1/risks/seed. Grounded + idempotent (CandidateRisks is deterministic; seedRisks never
	// overwrites a human's decision). Best-effort — a seeding error never affects the scan.
	risksProposed := 0
	if seeded, serr := d.seedRisks(ctx, tenantID); serr == nil {
		risksProposed = len(seeded)
	} else {
		slog.Warn("[auto-review] risk seeding failed", "tenant", tenantID, "err", serr)
	}
	// Persist the auto-review as the tenant's latest triage (like the on-demand path) so it survives to the
	// /brief console — the continuous engine's work is visible without the user re-running it.
	d.persistAIAnalysis(ctx, tenantID, "triage", "", "Auto-review after scan", out, time.Now())
	if d.Recorder != nil {
		d.Recorder.Record("ai engineer auto-reviewed", "l2-lead",
			map[string]any{"tenant_id": tenantID, "opened_incidents": openedIncidents, "reports": len(out.Findings), "risks_proposed": risksProposed, "summary": out.Summary},
			"AI Security Engineer auto-review after scan change")
	}
}

// hasPriorTriage reports whether the tenant already has a persisted whole-estate triage analysis (the
// "have we reviewed before" signal that bounds the continuous auto-review to change + first-run).
func (d Deps) hasPriorTriage(ctx context.Context, tenantID string) bool {
	all, err := d.Store.ListAIAnalyses(ctx, tenantID)
	if err != nil {
		return true // on a read error, be conservative: assume reviewed → don't spend the LLM
	}
	for _, a := range all {
		if a.Kind == "triage" {
			return true
		}
	}
	return false
}

// toIssueDigests maps crossdetect's unified issues into the engine-pure l2.IssueDigest the Lead prompt
// renders — the platform→engine boundary (l2 never imports crossdetect, so the platform does the map).
func toIssueDigests(issues []crossdetect.Issue) []l2.IssueDigest {
	out := make([]l2.IssueDigest, 0, len(issues))
	for _, is := range issues {
		out = append(out, l2.IssueDigest{
			Title:     is.Title,
			Severity:  is.Severity,
			Sources:   is.Tools,
			Confirmed: is.Confirmed,
			Count:     is.Count,
			Endpoint:  is.Endpoint,
			CVE:       is.CVE,
			Attacked:  is.Attacked,
		})
	}
	return out
}

// renderChains renders each cross-surface attack chain to a one-line "surface → surface → crown"
// summary for the Lead prompt. Capped so a large estate can't blow the prompt.
func renderChains(chains []correlate.Chain) []string {
	const cap = 20
	out := make([]string, 0, len(chains))
	for i, ch := range chains {
		if i >= cap {
			break
		}
		out = append(out, renderChain(ch))
	}
	return out
}

// renderChain renders one chain so the L2 Lead can reason about it WITHOUT drilling in: each
// hop names its actual finding (not just the bucketed asset target, which collapses distinct
// crowns), and the shared identifier that BRIDGES to the next hop is shown inline — so the
// Lead sees WHY the surfaces connect (the leaked key / email / ARN), the reasoning it otherwise
// couldn't explain. (Prior render dropped ViaEntity and used AssetTarget, making three chains
// to three different crowns look identical.)
func renderChain(ch correlate.Chain) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] ", ch.Severity)
	for i, s := range ch.Steps {
		if i > 0 {
			if bridge := ch.Steps[i-1].ViaEntity; bridge != "" {
				fmt.Fprintf(&b, " —[%s]→ ", bridge)
			} else {
				b.WriteString(" → ")
			}
		}
		label := s.AssetType
		if t := chainStepLabel(s); t != "" {
			label += " " + t
		}
		if s.CrownJewel {
			label += " (CROWN)"
		}
		b.WriteString(label)
	}
	return b.String()
}

// chainStepLabel is the step's own finding identity (title, else its target) — precise per
// step, so distinct crowns don't collapse to the asset's display target.
func chainStepLabel(s correlate.Step) string {
	if t := strings.TrimSpace(s.Title); t != "" {
		if len(t) > 70 {
			t = t[:70] + "…"
		}
		return "“" + t + "”"
	}
	return s.AssetTarget
}
