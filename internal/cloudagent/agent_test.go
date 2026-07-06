package cloudagent

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudquery"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// scriptedLLM returns canned JSON actions in order — drives the agent loop in CI
// with no API key. The real Gemini client plugs into the same cloudengine.LLM iface.
type scriptedLLM struct {
	replies []string
	i       int
}

func (s *scriptedLLM) Generate(_ context.Context, _ string) (string, error) {
	if s.i >= len(s.replies) {
		return `{"tool":"finish","args":{"summary":"done"}}`, nil
	}
	r := s.replies[s.i]
	s.i++
	return r, nil
}

var _ cloudengine.LLM = (*scriptedLLM)(nil)

func fixture(t *testing.T) *Context {
	t.Helper()
	ds, err := cloudquery.Generate()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	snap := cloudgraph.Ingest(cloudquery.ToInventory(ds.Tables))
	return &Context{Snap: snap, Prowler: cloudquery.EvalProwler(ds.Tables)}
}

const (
	pii     = "arn:aws:s3:::acme-customer-pii"
	ec2web  = "arn:aws:ec2:us-east-1:123456789012:instance/i-web"
	webRole = "arn:aws:iam::123456789012:role/web-role"
)

// TestAgent_InvestigatesAndGroundsAFinding drives the full brain→tools loop: the
// LLM enumerates, verifies a path, records a grounded issue, and gets a verified
// fix — all through the tool catalog, no deterministic spine.
func TestAgent_InvestigatesAndGroundsAFinding(t *testing.T) {
	cc := fixture(t)
	llm := &scriptedLLM{replies: []string{
		`{"thought":"seed with the deterministic prepass","tool":"enumerate_attack_paths","args":{}}`,
		`{"thought":"verify the PII path","tool":"find_paths","args":{"target":"` + pii + `"}}`,
		`{"thought":"confirmed; record it","tool":"record_issue","args":{"target":"` + pii + `","path":["internet","` + ec2web + `","` + webRole + `","` + pii + `"],"severity":"high","rationale":"internet-facing EC2 runs web-role which reads the PII bucket","evidence":["find_paths confirmed the chain"]}}`,
		`{"thought":"propose a fix","tool":"propose_fix","args":{"issue_id":"ai-001"}}`,
		`{"thought":"done","tool":"finish","args":{"summary":"1 real path to customer PII; verified fix proposed"}}`,
	}}

	rep, err := Investigate(context.Background(), llm, cc, Options{MaxIters: 20})
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if len(rep.Issues) != 1 {
		t.Fatalf("want 1 recorded issue, got %d", len(rep.Issues))
	}
	is := rep.Issues[0]
	if is.Target != pii {
		t.Errorf("issue target = %s, want the PII bucket", is.Target)
	}
	if !is.FixVerified {
		t.Errorf("propose_fix should have produced a cloudiam-verified remediation; got %+v", is)
	}
	if rep.Summary == "" {
		t.Error("finish should set an executive summary")
	}
}

// TestBuildPrompt_RendersCrossSurfaceBridges is the G2 guard: when the cloud specialist is given
// cross-surface footholds (a leaked key in code correlating into this account), the prompt must surface
// them as external entry points so the agent verifies paths FROM them first — the code→cloud wedge. With
// no bridges the section is absent (a purely-cloud investigation is unchanged).
func TestBuildPrompt_RendersCrossSurfaceBridges(t *testing.T) {
	cc := fixture(t)
	if strings.Contains(buildPrompt(cc, nil), "CROSS-SURFACE ENTRY POINTS") {
		t.Fatal("with no bridges the cross-surface section must be absent")
	}
	cc.Bridges = []string{`shared aws_key AKIA… bridges repository foothold "leaked AWS key in config.py" → cloud target "admin role"`}
	p := buildPrompt(cc, nil)
	if !strings.Contains(p, "CROSS-SURFACE ENTRY POINTS") {
		t.Error("the cross-surface entry-point section must render when bridges are present")
	}
	if !strings.Contains(p, "leaked AWS key in config.py") {
		t.Error("the bridge hint text must appear so the agent knows the code→cloud foothold")
	}
}

// TestAgent_RejectsUngroundedFinding is the anti-hallucination guard: a path that
// does not exist in the graph must be REJECTED, so the LLM cannot invent findings.
func TestAgent_RejectsUngroundedFinding(t *testing.T) {
	cc := fixture(t)
	llm := &scriptedLLM{replies: []string{
		// claim internet reaches the PII bucket directly — there is no such edge.
		`{"tool":"record_issue","args":{"target":"` + pii + `","path":["internet","` + pii + `"],"severity":"critical","rationale":"made up"}}`,
		`{"tool":"finish","args":{"summary":"none"}}`,
	}}
	rep, err := Investigate(context.Background(), llm, cc, Options{MaxIters: 10})
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if len(rep.Issues) != 0 {
		t.Errorf("an ungrounded path must be rejected, but %d issue(s) were recorded", len(rep.Issues))
	}
}

func TestDigestProwler_SurfacesL15(t *testing.T) {
	fs := []types.Finding{
		{ID: "p-1", Severity: types.SeverityHigh, RuleID: "prowler::s3-public", Endpoint: "arn:aws:s3:::bucket", Title: "public bucket",
			ThreatIntel:    &types.ThreatIntel{KEV: &types.KEVStatus{Listed: true}},
			Exploitability: &types.Exploitability{Score: 7},
			Compliance:     &types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"1.2"}}},
		{ID: "p-2", Severity: types.SeverityLow, RuleID: "prowler::tag", Endpoint: "arn:aws:ec2", Title: "missing tag"},
	}
	lines := digestProwler(fs)
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	// high finding first, with its L1.5 + compliance surfaced.
	if !strings.Contains(lines[0], "public bucket") {
		t.Fatalf("first line should be the high finding: %s", lines[0])
	}
	for _, want := range []string{"KEV", "exploit:7", "soc2", "pci"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("prowler digest missing L1.5 tag %q: %s", want, lines[0])
		}
	}
	if strings.Contains(lines[1], "  [") {
		t.Errorf("a bare prowler finding should carry no enrichment bracket: %s", lines[1])
	}
}
