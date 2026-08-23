package platformapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"

	"github.com/ClatTribe/tsengine/pkg/platform"
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
	llm := d.resolveAgentLLMForRole(r.Context(), tenantID, platform.RoleAnalysis)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, llmRequiredBody("Cloud investigation"))
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
		// The graph those bridges were a lossy proxy for. Bridges say WHERE a foothold is; the estate
		// lets the agent walk from it — back to the key's origin in code, or on to what else touches
		// the principal. Best-effort: a compose failure leaves it nil and estate_context says so.
		Estate: d.estateOrNil(r.Context(), tenantID),
		// Stage 1 live discovery: let the agent confirm a config flag against the account NOW rather
		// than trusting a snapshot captured before it started. Nil when no live path is configured,
		// and check_live says so.
		Live: d.liveReaderOrNil(r.Context(), tenantID),
		// ADR 0024 P1: ask the PROVIDER whether a move is authorized, rather than inferring it from
		// our own resolved-IAM graph. Nil when the tenant has no connected account or the deployment
		// has no live path — check_reachable then says the provider was not asked (§10).
		Prober: d.proberOrNil(r.Context(), tenantID),
	}
	// Bracket the run (ADR 0018 §4). The before-state has to be censused HERE, before the
	// agent acts — after the fact there is no way to tell an issue the agent surfaced from
	// one that was already on the books, and a corpus that cannot tell those apart credits
	// the agent with the estate's whole backlog.
	episode := ledger.NewEpisode(nil, d.censusState(r.Context(), tenantID, "cloud:"+tenantID, cloudFinding))
	episode.AgentVersion = agentVersion()
	// Stamp the standing decision HERE, before the run produces anything. Consent has to
	// be in hand before the data exists — ledger.GrantConsent refuses after Close for
	// exactly that reason, so asking afterwards would be asking a question the system is
	// built to refuse.
	d.applyTrainingConsent(r.Context(), tenantID, episode)
	started := time.Now()

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
		built = append(built, cloudIssueToFinding(d.newID("cloudagent")+"-"+strconv.Itoa(i), is, rep.Probes))
	}
	stored := 0
	saved := make([]types.Finding, 0, len(built))
	for _, f := range enrichFindings(built) {
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
	// Agent proposes → named vCISO disposes (§18.4): the agent's proven attack paths cluster into
	// candidate risks on the vCISO desk automatically, so the human judges the agent's discoveries.
	risksProposed := 0
	if stored > 0 {
		if seeded, serr := d.seedRisks(r.Context(), tenantID); serr == nil {
			risksProposed = len(seeded)
		}
	}
	// Close the bracket. A scope mismatch or an unreadable store leaves Delta nil, and
	// the episode is still recorded — an unscorable run is a real run, and dropping it
	// would bias the record toward the ones that went smoothly.
	episode.Cost = ledger.Cost{Iterations: rep.Calls, WallClock: time.Since(started)}
	_ = episode.Close(d.censusState(r.Context(), tenantID, "cloud:"+tenantID, cloudFinding))
	d.recordEpisode(r.Context(), tenantID, "cloud:"+tenantID, episode, saved)

	if d.Recorder != nil {
		args := map[string]any{"tenant_id": tenantID, "paths": stored, "calls": rep.Calls, "risks_proposed": risksProposed}
		if dl := episode.Delta; dl != nil {
			// The measured effect of THIS run, not a restatement of what it reported.
			// opened counts issues that were not on the books before it started;
			// closed only means they stopped appearing, which is not the same as fixed.
			args["opened"] = len(dl.Opened)
			args["closed"] = len(dl.Closed)
			args["persisted"] = dl.Persisted
		} else {
			args["delta"] = "unscored — posture could not be censused on both sides of the run"
		}
		d.Recorder.Record("cloud investigated", "cloudagent", args, "AI Cloud Engineer investigation")
	}
	resp := map[string]any{"summary": rep.Summary, "paths_found": stored, "risks_proposed": risksProposed, "calls": rep.Calls, "issues": rep.Issues}
	if rep.Probes != nil {
		// What the provider was actually ASKED and what it answered, denials included. Omitted
		// entirely when no dry-run path was wired, because a zeroed tally would read as an account
		// that was checked and came back clean (§10).
		resp["probe_coverage"] = rep.Probes
	}
	if episode.Delta != nil {
		resp["posture_delta"] = episode.Delta
	}
	writeJSON(w, http.StatusOK, resp)
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
		"enabled": d.resolveAgentLLMForRole(r.Context(), tenantID, platform.RoleAnalysis) != nil, // tenant model OR operator-global → runnable
	})
}

// cloudPathRuleID makes each distinct ROUTE its own finding identity.
//
// detect.Key is RuleID|Endpoint, and the endpoint here is the crown jewel the path ends at. With a
// constant rule id, two DIFFERENT proven routes to the SAME crown jewel — say an exposed EC2 role and
// a separate leaked key, both reaching the same bucket — collapsed to one key, so the second silently
// masked the first in incidents and unified issues. That is the exact failure the CODE path already
// guards against by folding the assessed finding id into its rule id ("otherwise the second would mask
// the first ... silently dropping a confirmed-exploitable vuln"); the cloud path needed the same.
//
// The route itself is the stable discriminator: every node is a real graph id validated by
// validatePath, so the same route digests identically on every run (no churn), while a genuinely
// different route gets its own key and its own incident. The agent's own issue counter (ai-001) would
// NOT do — it is per-run sequential, so it would change identity on every scan.
func cloudPathRuleID(path []string) string {
	if len(path) == 0 {
		return "cloudagent::attack-path"
	}
	sum := sha256.Sum256([]byte(strings.Join(path, ">")))
	return "cloudagent::attack-path::" + hex.EncodeToString(sum[:])[:12]
}

// cloudIssueToFinding maps an agent-proven attack path to a stored finding (verified — the agent only
// records paths it confirmed via the graph tools, §10).
func cloudIssueToFinding(id string, is cloudagent.Issue, probes *cloudagent.ProbeCoverage) types.Finding {
	// The agent's PATH is grounded (validatePath proves every edge and a crown-jewel endpoint), but
	// its severity is free text the model chose. An unrecognised value ("P1", "moderate") ranks 0 —
	// BELOW info — so it would sort under every informational note AND fall under detect's threshold,
	// silently opening no incident. A proven path to a crown jewel must never be silenced by a
	// spelling. Not Valid() gets the same conservative default as empty.
	sev := types.Severity(strings.ToLower(strings.TrimSpace(is.Severity)))
	if !sev.Valid() {
		sev = types.SeverityHigh
	}
	desc := is.Rationale
	if is.Remediation != "" {
		desc += "\n\nRemediation: " + is.Remediation
	}
	// The agent computes which rung of the verification ladder this path sits on (ADR 0024 P1) and
	// both fields were dropped here, so the strongest evidence the cloud engineer can produce died
	// inside the agent struct: nothing downstream — store, issues, incidents, GRC, UI — could tell a
	// provider-confirmed path from a purely config-possible one.
	rawOut, _ := json.Marshal(map[string]any{
		"path": is.Path, "evidence": is.Evidence, "fix_kind": is.FixKind, "fix_verified": is.FixVerified, "fix_content": is.FixContent,
		"provider_confirmed": is.ProviderConfirmed, "authorization_coverage": is.AuthorizationCoverage,
	})
	desc += "\n\n" + authorizationRungLine(is)
	// A provider proof is a point-in-time answer, and this is the only surface a human reads it on
	// (ADR 0024 P1c / C4). Stating the rung without stating WHEN and AGAINST WHAT renders a proof
	// taken three weeks ago against a since-re-scoped account identically to one taken a minute ago.
	if line := proofProvenanceLine(is, probes); line != "" {
		desc += " " + line
	}
	title := is.TargetName
	if title == "" {
		title = is.Target
	}
	return types.Finding{
		ID: id, RuleID: cloudPathRuleID(is.Path), Tool: "cloudagent", Severity: sev,
		Endpoint: is.Target, Title: title + " — reachable attack path", Description: desc,
		VerificationStatus: authorizationRungStatus(is), RawOutput: rawOut, DiscoveredAt: time.Now().UTC(),
	}
}

// authorizationRungStatus maps the verification ladder (ADR 0024 C3) onto types.VerificationState.
//
// It used to be the constant types.VerificationVerified, on every path the agent recorded, at every
// rung. That is the strongest evidence tier this product has, and its own definition is "independent
// method(s) ACTIVELY confirmed it" — so a path resting on nothing but our resolved-IAM graph was
// handed the authority of one the cloud provider had been asked about and had confirmed.
//
// The cost was not internal. VerificationStatus is the field two CUSTOMER-FACING surfaces read:
// grc/vapt.isVerified counts it as "tool-confirmed" in the report a customer hands an auditor, and
// explain.urgency turns it into "we proved it is exploitable on your system, not just possible".
// Both of those sentences were being written about a path nobody had checked with anything.
//
// The mapping below is not a judgement call — each tier's own doc comment decides it:
//
//	config_possible  → pattern_match. ONE source: our inventory. validatePath re-checks every edge,
//	                   but against the SAME graph, so nothing independent has agreed and nothing was
//	                   actively re-fired. This is the honest floor, and it is where most paths sit.
//	PARTIAL          → corroborated. "≥2 INDEPENDENT assessments agreed ... without re-firing
//	                   anything" — our graph and the provider, agreeing on a subset of the hops.
//	provider-confirmed → verified. "independent method(s) ACTIVELY confirmed it": the provider's own
//	                   policy simulator was called, per hop, and allowed every one.
//
// Note what verified still does NOT mean here, and why explain.go needs its own guard: it means the
// AUTHORIZATION is confirmed, never that the path was exploited (ADR 0024 C1).
//
// The sibling made this call correctly first — codeinvestigate.go refuses `verified` for the code
// agent and spends eleven lines saying why. This is that reasoning applied to the other agent.
func authorizationRungStatus(is cloudagent.Issue) types.VerificationState {
	switch {
	case is.ProviderConfirmed:
		return types.VerificationVerified
	case is.AuthorizationCoverage != "" && is.AuthorizationCoverage != "0/0":
		return types.VerificationCorroborated
	default:
		return types.VerificationPatternMatch
	}
}

// authorizationRungLine states which rung of the verification ladder a recorded path stands on, in
// the description a human actually reads.
//
// Silence here is not neutral: rendered without it, a path proven only by OUR resolved-IAM graph and
// one confirmed hop-by-hop by the provider's own policy simulator look identical, and the reader
// supplies the stronger reading. A PARTIAL proof is the case that most needs saying — "3 of 5 hops
// authorized" is real evidence and is not the same claim as a complete one.
func authorizationRungLine(is cloudagent.Issue) string {
	const caveat = " This confirms AUTHORIZATION, not exploitability: network reachability, " +
		"credential acquisition, unsupplied session context and the rest of the workflow stay unproven."
	switch {
	case is.ProviderConfirmed:
		return "Verification: provider-confirmed authorization (" + is.AuthorizationCoverage +
			" authorization-requiring hops confirmed ALLOW by the cloud provider's own policy simulator)." + caveat
	case is.AuthorizationCoverage != "" && is.AuthorizationCoverage != "0/0":
		return "Verification: PARTIAL — " + is.AuthorizationCoverage + " authorization-requiring hops " +
			"confirmed ALLOW by the provider's own policy simulator; the remaining hops are config-possible " +
			"only (our resolved-IAM graph says the permission exists, the provider was not asked or could " +
			"not answer)." + caveat
	default:
		return "Verification: config-possible — this path comes from our resolved-IAM graph. No provider " +
			"dry-run confirmed its hops, which is not the same as the path being denied or closed."
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
		llm := d.resolveAgentLLMForRole(ctx, tenantID, platform.RoleAnalysis)
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
			Estate:  d.estateOrNil(ctx, tenantID),        // the walkable graph behind those hints
			Live:    d.liveReaderOrNil(ctx, tenantID),    // confirm config flags against the live account
			Prober:  d.proberOrNil(ctx, tenantID),        // ADR 0024 P1: the provider's own authorization answer
		}
		// Bounded specialist run (it's a nested agent — keep it tight). pentest.SpecLLM satisfies
		// cloudengine.LLM structurally (same Generate), as the on-demand handler above relies on.
		rep, ierr := cloudagent.Investigate(ctx, llm, cc, cloudagent.Options{MaxIters: 12, MaxHyp: 12})
		if ierr != nil {
			return "Cloud investigation error: " + ierr.Error(), nil
		}
		_ = focus // the specialist explores the whole graph; focus is the generalist's framing hint

		// SAY HOW OLD THE PICTURE IS. This path reasons over a STORED snapshot, and until the live
		// describe-* fetcher lands, its age is bounded only by when someone last posted one. A
		// conclusion drawn from a month-old inventory reads exactly like one drawn from this
		// morning's unless we say otherwise — and the reader cannot tell, because only we know
		// CapturedAt. Leading with it means the generalist carries the caveat into whatever it tells
		// the customer, rather than the caveat living in a field nobody surfaces.
		out := cloudagent.Render(rep)
		if note := snapshotAgeNote(snap.CapturedAt, time.Now().UTC()); note != "" {
			out = note + "\n\n" + out
		}
		return out, nil
	}
}

// proofProvenanceLine states when a provider proof was obtained and which account state it was
// evaluated against.
//
// Only for findings that actually STAND on a provider answer: a config-possible path has no proof to
// date, and stamping one with a snapshot hash would dress our own graph up as something the provider
// had been asked about. Empty when there is nothing honest to say — silence here costs nothing,
// whereas a provenance line on an unproven claim is the overclaim this whole rung exists to prevent.
func proofProvenanceLine(is cloudagent.Issue, probes *cloudagent.ProbeCoverage) string {
	if probes == nil {
		return ""
	}
	if !is.ProviderConfirmed && (is.AuthorizationCoverage == "" || is.AuthorizationCoverage == "0/0") {
		return ""
	}
	f := probes.Freshness
	if f.ObtainedAt == "" {
		return ""
	}
	line := "Obtained at " + f.ObtainedAt
	if f.SnapshotHash != "" {
		// The hash is what makes the claim re-checkable: an auditor can re-run the same tuples
		// against the same recorded state (§10's reproducibility base).
		line += " against account state " + shortSnapshot(f.SnapshotHash)
	}
	return line + ". A provider answer describes that moment; re-check it after any IAM, trust-policy " +
		"or SCP change."
}

func shortSnapshot(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
