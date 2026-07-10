package bench

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// l2lead.go benchmarks the L2 LEAD generalist (internal/l2) — the agent that reasons over the
// WHOLE cross-surface estate (unified issues + correlation chains) and triages it for a
// developer. Where the cloud/code specialists go deep on one surface, the Lead's job is
// breadth + prioritization: connect the three-scanners-one-attack-path story and lead with
// the crown-jewel chain, not the noise. This harness feeds it the SAME correlation estate the
// correlation bench plants, runs the real agent loop over a supplied Client (the dev proxy =
// frontier Claude, or a mock), and scores the OUTCOME — did it surface the cross-surface
// attack path, prioritize the crown, and stay grounded (no invented findings, §10).

// L2LeadResult scores one L2 Lead run over the estate.
type L2LeadResult struct {
	Ran                bool     `json:"ran"`
	Iterations         int      `json:"iterations"`
	CommittedFindings  int      `json:"committed_findings"`
	SurfacedAttackPath bool     `json:"surfaced_attack_path"` // exec summary connects a cross-surface chain to a crown jewel
	LedWithCrown       bool     `json:"led_with_crown"`       // the crown-jewel chain is prioritized (named in the summary)
	Invented           []string `json:"invented,omitempty"`   // committed finding titles grounded in NO estate entity (§10)
	ExecutiveSummary   string   `json:"executive_summary,omitempty"`
	Err                string   `json:"error,omitempty"`
}

// Pass: it surfaced + prioritized the cross-surface crown path and invented nothing.
func (r L2LeadResult) Pass() bool {
	return r.Ran && r.SurfacedAttackPath && r.LedWithCrown && len(r.Invented) == 0
}

// estateFor builds the L2 EstateContext from the correlation estate (the real product path:
// unified issues + rendered attack chains).
func estateFor(fs []types.Finding) l2.EstateContext {
	return l2.EstateContext{
		Issues:      benchIssueDigests(crossdetect.UnifiedIssues(fs)),
		AttackPaths: benchRenderChains(crossdetect.Correlate(nil, fs)),
	}
}

func benchIssueDigests(issues []crossdetect.Issue) []l2.IssueDigest {
	out := make([]l2.IssueDigest, 0, len(issues))
	for _, is := range issues {
		out = append(out, l2.IssueDigest{
			Title: is.Title, Severity: is.Severity, Sources: is.Tools,
			Confirmed: is.Confirmed, Count: is.Count, Endpoint: is.Endpoint, CVE: is.CVE, Attacked: is.Attacked,
		})
	}
	return out
}

// benchRenderChains mirrors the platform's improved chain render: each hop names its own
// finding and the bridging entity is shown inline (see internal/platformapi.renderChain), so
// the Lead sees WHY the surfaces connect and distinct crowns don't collapse.
func benchRenderChains(chains []correlate.Chain) []string {
	out := make([]string, 0, len(chains))
	for _, ch := range chains {
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
			if t := strings.TrimSpace(s.Title); t != "" {
				label += " \"" + t + "\""
			} else {
				label += ":" + s.AssetTarget
			}
			if s.CrownJewel {
				label += " (CROWN)"
			}
			b.WriteString(label)
		}
		out = append(out, b.String())
	}
	return out
}

// RunL2LeadBench runs the L2 Lead over the correlation estate with the given client and scores
// its triage. The client is the caller's (the dev proxy for a frontier run, or a mock in CI).
func RunL2LeadBench(ctx context.Context, client l2.Client) L2LeadResult {
	fs, _ := correlationEstate()
	estate := estateFor(fs)
	target := types.Asset{Type: "repository", Target: "acme/monorepo"}

	budget := l2.DefaultBudget()
	budget.MaxIterations = 16
	agent, err := l2.New(client, l2.BuildCatalog(l2.Deps{Target: target, L1Findings: fs}), budget)
	if err != nil {
		return L2LeadResult{Err: err.Error()}
	}
	agent.WithEstate(estate)
	outcome, rerr := agent.Run(ctx, target, fs)
	r := L2LeadResult{Ran: true, Iterations: outcome.Iterations, CommittedFindings: len(outcome.Findings)}
	if rerr != nil {
		r.Err = rerr.Error()
	}
	if outcome.Summary != nil {
		r.ExecutiveSummary = outcome.Summary.ExecutiveSummary
	}
	scoreLeadTriage(&r, fs, outcome)
	return r
}

// scoreLeadTriage measures cross-surface awareness + prioritization + grounding from the
// Lead's committed findings + executive summary.
func scoreLeadTriage(r *L2LeadResult, fs []types.Finding, outcome l2.Outcome) {
	blob := strings.ToLower(r.ExecutiveSummary)
	for _, f := range outcome.Findings {
		blob += " " + strings.ToLower(f.Title+" "+f.Description)
	}
	// surfaced the cross-surface attack path: an initial-access signal (leaked key / SSRF / MFA)
	// connected to a cloud crown (admin / privesc / PII).
	entry := containsAny(blob, "leak", "hardcoded", "ssrf", "mfa", "credential", "secret", "access key")
	crown := containsAny(blob, "admin", "administrator", "privilege", "privesc", "escalat", "pii", "crown", "cloud")
	r.SurfacedAttackPath = entry && crown
	// led with the crown: the summary explicitly frames the chain / attack path / reaching the crown.
	r.LedWithCrown = containsAny(blob, "attack path", "chain", "reaches", "pivot", "lateral", "leads to", "→", "reach the")
	// grounding (§10): create_vulnerability_report ALREADY refuses a report whose evidence_finding_ids
	// don't exist, so a committed finding is grounded by construction. What a benchmark still catches is
	// a FABRICATED SPECIFIC IDENTIFIER in the narrative — an ARN / AWS key / CVE / email that appears
	// nowhere in the estate (the model inventing a concrete fact). Only those count as invented.
	estate := strings.ToLower(estateBlob(fs))
	for _, f := range outcome.Findings {
		for _, id := range specificIdentifiers(f.Title + " " + f.Endpoint + " " + f.Description) {
			if !strings.Contains(estate, strings.ToLower(id)) {
				r.Invented = append(r.Invented, id)
			}
		}
	}
}

// estateBlob is all the text a grounded report could legitimately cite.
func estateBlob(fs []types.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.ID + " " + f.RuleID + " " + f.Title + " " + f.Endpoint + " " + f.Description + " ")
	}
	return b.String()
}

var (
	reARN   = regexp.MustCompile(`arn:aws:[a-z0-9-]*:[a-z0-9-]*:\d{12}:[\w./:*-]+`)
	reKey   = regexp.MustCompile(`AKIA[A-Z0-9]{16}`)
	reCVE   = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)
	reEmail = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
)

// specificIdentifiers extracts concrete, checkable identifiers a report might fabricate.
func specificIdentifiers(s string) []string {
	var out []string
	for _, re := range []*regexp.Regexp{reARN, reKey, reCVE, reEmail} {
		out = append(out, re.FindAllString(s, -1)...)
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// RenderL2LeadMarkdown renders the L2 Lead scoreboard.
func RenderL2LeadMarkdown(r L2LeadResult) string {
	var b strings.Builder
	b.WriteString("\n## L2 Lead triage (frontier LLM via proxy)\n\n")
	b.WriteString("_The generalist over the whole cross-surface estate — did it connect the three-scanners-")
	b.WriteString("one-attack-path story, lead with the crown-jewel chain, and stay grounded (§10)._\n\n")
	yn := func(b bool) string {
		if b {
			return "✓"
		}
		return "✗"
	}
	fmt.Fprintf(&b, "- surfaced cross-surface attack path: **%s** · led with the crown chain: **%s** · invented findings: **%d** · iterations: %d · committed: %d\n",
		yn(r.SurfacedAttackPath), yn(r.LedWithCrown), len(r.Invented), r.Iterations, r.CommittedFindings)
	if r.ExecutiveSummary != "" {
		fmt.Fprintf(&b, "\n> %s\n", strings.ReplaceAll(r.ExecutiveSummary, "\n", " "))
	}
	if r.Err != "" {
		fmt.Fprintf(&b, "\n_error: %s_\n", r.Err)
	}
	return b.String()
}
