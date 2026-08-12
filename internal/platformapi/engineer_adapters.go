package platformapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// engineer_adapters.go backs the agent's acting tool belt (internal/l2/tools_engineer.go) with the
// real store, the real remediation proposer and the real HITL desk.
//
// Without these the tools exist but every one degrades to "not available" — honest, and useless. This
// is what makes the agent an engineer rather than an analyst: it can now find out what it is dealing
// with, and it can propose a change a human will see.
//
// Every adapter is tenant-scoped by construction: the tenant id is bound when the adapter is built,
// never taken from a model argument. An agent cannot reach another tenant's data by asking for it —
// §18.2 inv. 2 is not something a tool argument gets to negotiate.

// ---------- estate search ----------

// estateSearch answers "what do I have?" over the tenant's own findings and assets.
//
// It is deliberately a KEYWORD-AND-FACET search, not an LLM one. The agent already has a model; what
// it lacks is data. Adding a second model here would put a paraphrase between the agent and the
// truth, and a wrong answer about your own estate is worse than no answer.
type estateSearch struct {
	d        Deps
	tenantID string
}

func (s estateSearch) Search(ctx context.Context, query string) (string, error) {
	findings, err := s.d.Store.ListFindings(ctx, s.tenantID, store.FindingFilter{})
	if err != nil {
		return "", err
	}
	assets, _ := s.d.Store.ListAssets(ctx, s.tenantID)

	q := strings.ToLower(strings.TrimSpace(query))
	terms := strings.Fields(q)

	// Facets the agent asks for constantly, recognised from plain language so it does not have to
	// learn a query syntax it was never taught.
	wantUnproven := strings.Contains(q, "unproven") || strings.Contains(q, "unverified")
	wantProven := strings.Contains(q, "proven") && !wantUnproven
	wantCritical := strings.Contains(q, "critical")
	wantHigh := strings.Contains(q, "high")

	var hits []types.Finding
	for _, f := range findings {
		if wantUnproven && f.VerificationStatus == types.VerificationVerified {
			continue
		}
		if wantProven && f.VerificationStatus != types.VerificationVerified {
			continue
		}
		sev := strings.ToLower(string(f.Severity))
		if wantCritical && !wantHigh && sev != "critical" {
			continue
		}
		if wantHigh && !wantCritical && sev != "high" {
			continue
		}
		if wantCritical && wantHigh && sev != "critical" && sev != "high" {
			continue
		}
		if !matchesTerms(f, terms) {
			continue
		}
		hits = append(hits, f)
	}
	// Worst first — an agent reading a truncated list should see the things that matter.
	sort.SliceStable(hits, func(i, j int) bool { return sevRank(hits[i].Severity) < sevRank(hits[j].Severity) })

	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d findings match; %d assets monitored.\n", len(hits), len(findings), len(assets))
	if len(hits) == 0 {
		// State the negative precisely. "Nothing matched" and "we have no data" look identical to an
		// agent, and only one of them means the estate is clean.
		if len(findings) == 0 {
			b.WriteString("This tenant has NO findings recorded at all — nothing has been scanned yet, " +
				"which is not the same as being clean.")
		} else {
			b.WriteString("No finding matches that. The estate has findings, just none matching these terms.")
		}
		return b.String(), nil
	}
	const cap = 25
	for i, f := range hits {
		if i >= cap {
			fmt.Fprintf(&b, "… and %d more (refine the query).\n", len(hits)-cap)
			break
		}
		fmt.Fprintf(&b, "- [%s] %s · %s · %s · %s\n",
			f.ID, f.Title, f.Severity, nz(string(f.VerificationStatus), "unverified"), nz(f.Endpoint, "no endpoint"))
	}
	return b.String(), nil
}

func matchesTerms(f types.Finding, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{
		f.Title, f.RuleID, f.Tool, f.Endpoint, f.Description, strings.Join(f.CWE, " "),
	}, " "))
	// Any-term match: a security engineer typing "log4j rce" wants either word, not both.
	for _, t := range terms {
		if len(t) > 2 && strings.Contains(hay, t) {
			return true
		}
	}
	return false
}

func sevRank(s types.Severity) int {
	switch strings.ToLower(string(s)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

// ---------- propose a fix ----------

// fixProposer turns the agent's intent into a queued platform.Action.
//
// It reuses remediate.Propose rather than letting the model author the remediation directly. That is
// the §10 split: the agent DECIDES what needs fixing (judgement, which it is good at) and the
// deterministic proposer produces WHAT the fix is (a grounded action for that finding class, which a
// model would happily invent). The agent's rationale rides along for the human reviewer.
type fixProposer struct {
	d        Deps
	tenantID string
}

func (p fixProposer) ProposeFix(ctx context.Context, findingID, rationale string) (string, error) {
	if p.d.Submitter == nil || p.d.NewID == nil {
		return "", fmt.Errorf("remediation is not configured in this deployment")
	}
	findings, err := p.d.Store.ListFindings(ctx, p.tenantID, store.FindingFilter{})
	if err != nil {
		return "", err
	}
	var target *types.Finding
	for i := range findings {
		if findings[i].ID == findingID {
			target = &findings[i]
			break
		}
	}
	// Grounding: the agent may only propose a fix for a finding that actually exists. A hallucinated
	// id must fail loudly here rather than become a queued action a human has to work out is fictional.
	if target == nil {
		return "", fmt.Errorf("no finding %q in this tenant — propose fixes only for findings you have seen", findingID)
	}

	assets, _ := p.d.Store.ListAssets(ctx, p.tenantID)
	asset := assetForFinding(assets, *target)
	act, ok := remediate.Propose(*target, asset, func() string { return p.d.newID("rem") })
	if !ok {
		return "", fmt.Errorf("no remediation path exists for %s (%s) — consider open_ticket instead", findingID, target.RuleID)
	}
	if r := strings.TrimSpace(rationale); r != "" {
		if act.Payload == nil {
			act.Payload = map[string]any{}
		}
		// Namespaced so it can never collide with a payload key the connector routes on — the human
		// reads it, the delivery path ignores it.
		act.Payload["agent_rationale"] = r
	}
	queued, serr := p.d.Submitter.Submit(ctx, act)
	if serr != nil {
		return "", serr
	}
	return queued.ID, nil
}

// ---------- request proof ----------

// proofRequester hands an unproven finding to the offensive side.
//
// It reuses pentest.SelectForProof so routing obeys the same gates as the monitoring pass: the class
// must be one a driver can actually demonstrate, and the target must be ownership-verified. A tool
// call is not a way around the ownership gate.
type proofRequester struct {
	d        Deps
	tenantID string
}

func (r proofRequester) RequestProof(ctx context.Context, findingID string) (string, error) {
	findings, err := r.d.Store.ListFindings(ctx, r.tenantID, store.FindingFilter{})
	if err != nil {
		return "", err
	}
	var target []types.Finding
	for _, f := range findings {
		if f.ID == findingID {
			target = append(target, f)
			break
		}
	}
	if len(target) == 0 {
		return "", fmt.Errorf("no finding %q in this tenant", findingID)
	}
	owned, _ := r.d.ownedTargets(ctx, r.tenantID)
	reqs := pentest.SelectForProof(target, owned, 1)
	if len(reqs) == 0 {
		// Say WHICH gate refused, because the two mean opposite things to the agent: one is "we
		// cannot test this class", the other is "you have not proven you own this".
		if len(owned) == 0 {
			return "This target is not ownership-verified, so active testing is not permitted. " +
				"Verify asset ownership first — this is not a statement about the finding.", nil
		}
		return "No offensive driver can demonstrate this finding's class, so an attempt would prove " +
			"nothing either way. Treat it as unresolved, not as a false positive.", nil
	}
	return fmt.Sprintf("Queued %s (%s) on %s for an exploitation attempt. A successful exploit proves "+
		"it; a failed one proves nothing either way.", reqs[0].FindingID, reqs[0].Class, reqs[0].Target), nil
}

// ---------- verify a fix ----------

type fixVerifier struct {
	d        Deps
	tenantID string
}

func (v fixVerifier) VerifyStatus(ctx context.Context, actionID string) (string, error) {
	acts, err := v.d.Store.ListActions(ctx, v.tenantID)
	if err != nil {
		return "", err
	}
	for _, a := range acts {
		if a.ID != actionID {
			continue
		}
		if a.Verification == nil {
			return fmt.Sprintf("%s is %s — not re-tested yet. A fix is only confirmed once a fresh scan "+
				"shows the finding gone.", actionID, a.Status), nil
		}
		return fmt.Sprintf("%s: %s — %s", actionID, a.Verification.Status, nz(a.Verification.Evidence, "no evidence recorded")), nil
	}
	return "", fmt.Errorf("no action %q in this tenant", actionID)
}

// ---------- file a ticket ----------

type ticketFiler struct {
	d        Deps
	tenantID string
}

// FileTicket raises a ticket about a real finding, and REFUSES otherwise.
//
// The refusal is the point. This adapter writes an Action into the tenant's queue that auto-delivers
// at tier 1, so whatever the model says here reaches a human's tracker unreviewed. Resolving the
// finding first is what stops that from being a channel for anything the model believes: the id has to
// name something the engine actually found, in THIS tenant, or nothing is filed.
//
// It also fills the context a receiver needs. A handoff reading "upgrade the vendor library" is not
// actionable by someone on another team who was not in the conversation — they need what was found,
// how bad it is, where it lives, and which tool said so, without coming back to ask.
func (t ticketFiler) FileTicket(ctx context.Context, findingID, title, body string) (string, error) {
	if t.d.Submitter == nil || t.d.NewID == nil {
		return "", fmt.Errorf("ticketing is not configured")
	}
	if strings.TrimSpace(findingID) == "" {
		return "", fmt.Errorf("a ticket must cite the finding it is about")
	}
	// Resolve against THIS tenant's findings — which also makes a cross-tenant id unresolvable rather
	// than merely unauthorized (§18.2 inv. 2).
	findings, err := t.d.Store.ListFindings(ctx, t.tenantID, store.FindingFilter{})
	if err != nil {
		return "", err
	}
	var found *types.Finding
	for i := range findings {
		if findings[i].ID == findingID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		return "", fmt.Errorf("no finding %q in this tenant — a ticket must describe something the "+
			"engine actually found, so nothing was filed", findingID)
	}

	// A ticket is informational and reversible, so it rides as a tier-1 action through the same desk
	// rather than getting its own delivery path.
	act := platform.Action{
		ID: t.d.newID("rem"), TenantID: t.tenantID, Kind: platform.ActFileTicket, Tier: 1,
		Status: platform.ActProposed, Title: title, FindingID: found.ID,
		Payload: map[string]any{
			"summary":    body,
			"raised_by":  "ai-security-engineer",
			"finding_id": found.ID,
			// The evidence a receiver on another team needs to act without coming back to ask.
			"severity":    string(found.Severity),
			"location":    found.Endpoint,
			"detected_by": found.Tool,
			"rule":        found.RuleID,
			"finding":     found.Title,
		},
	}
	queued, err := t.d.Submitter.Submit(ctx, act)
	if err != nil {
		return "", err
	}
	return queued.ID, nil
}

// EngineerCatalog builds the acting tool belt bound to one tenant.
//
// Binding the tenant HERE — not in a tool argument — is what keeps isolation non-negotiable: there is
// no argument an agent could supply that would reach another tenant's data.
func (d Deps) EngineerCatalog(tenantID string) l2.Catalog {
	return l2.EngineerTools(
		estateSearch{d: d, tenantID: tenantID},
		fixProposer{d: d, tenantID: tenantID},
		proofRequester{d: d, tenantID: tenantID},
		fixVerifier{d: d, tenantID: tenantID},
		ticketFiler{d: d, tenantID: tenantID},
		vulnLocalizer{d: d, tenantID: tenantID},
	)
}

// ---------- localize ----------

// vulnLocalizer ships T2. codelocalize scored 1.00 on its benchmark with NO customer-reachable call
// site, so no customer had ever received a localization — a capability measured, published and not
// delivered.
//
// It is wired here rather than into the L1.5 hook chain deliberately. The hook chain runs on EVERY
// finding at emission and must stay reproducible for the evidence pack; localization is a question the
// engineer asks about ONE finding when the location is in doubt, which is exactly a tool call. This
// also avoids changing a hot path for a capability whose value is per-investigation, not per-finding.
type vulnLocalizer struct {
	d        Deps
	tenantID string
}

func (v vulnLocalizer) Locate(ctx context.Context, findingID string) (string, error) {
	findings, err := v.d.Store.ListFindings(ctx, v.tenantID, store.FindingFilter{})
	if err != nil {
		return "", err
	}
	var target *types.Finding
	for i := range findings {
		if findings[i].ID == findingID {
			target = &findings[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("no finding %q in this tenant", findingID)
	}
	src, repo := v.d.codeSourceFor(ctx, v.tenantID)
	if src == nil {
		return "Localization needs source access — connect a repository first. " +
			"This is not a statement about the finding.", nil
	}
	// Build the candidate set from the repo's own file list, so a ranking can only ever cite files that
	// really exist (§10 — never a localization onto an invented path).
	var repoFiles codelocalize.Repo
	for _, p := range src.Files() {
		content, rerr := src.ReadFile(ctx, p, 0, 0)
		if rerr != nil || strings.TrimSpace(content) == "" {
			continue
		}
		repoFiles = append(repoFiles, codelocalize.File{Path: p, Content: content})
	}
	if len(repoFiles) == 0 {
		return "No readable source files in " + repo + " — cannot localize.", nil
	}
	res, lerr := codelocalize.HeuristicLocalizer{}.Localize(ctx,
		codelocalize.Query{CWE: target.CWE, Title: target.Title, Description: target.Description}, repoFiles)
	if lerr != nil {
		return "", lerr
	}
	if len(res.Ranked) == 0 {
		// An honest negative: no sink evidence for this class is a real answer, not a failure.
		return fmt.Sprintf("No file in %s carries sink evidence for %s — the finding may be a "+
			"configuration or dependency issue rather than a code one.", repo, strings.Join(target.CWE, ",")), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Ranked candidates in %s for %s:\n", repo, strings.Join(target.CWE, ","))
	for i, c := range res.Ranked {
		if i >= 5 {
			break
		}
		fmt.Fprintf(&b, "  %d. %s (score %.1f)", i+1, c.Path, c.Score)
		if len(c.SinkLines) > 0 {
			fmt.Fprintf(&b, " lines=%v", c.SinkLines)
		}
		b.WriteString("\n")
		for _, r := range c.Reasons {
			fmt.Fprintf(&b, "       %s\n", r)
		}
	}
	return b.String(), nil
}
