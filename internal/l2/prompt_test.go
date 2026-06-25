package l2

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestBuildSystemPrompt_ClearsRenderGuardAndDigestsFindings(t *testing.T) {
	l1 := []types.Finding{
		{ID: "f-2", Severity: types.SeverityLow, RuleID: "nuclei::info", Endpoint: "https://x/a", Title: "info"},
		{ID: "f-1", Severity: types.SeverityCritical, RuleID: "sqlmap::sqli", Endpoint: "https://x/p?id=1", Title: "SQLi"},
	}
	p := BuildSystemPrompt(types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, l1)

	// Render guard: a real prompt always clears the floor.
	if len(p) < minSystemPromptBytes {
		t.Fatalf("prompt %d bytes < floor %d", len(p), minSystemPromptBytes)
	}
	// Evidence-only + no-redetect rules present.
	for _, want := range []string{"NOT to detect", "Never invent", "L1 findings (2)"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	// Critical finding digested before the low one (severity-sorted, stable).
	ci := strings.Index(p, "f-1")
	li := strings.Index(p, "f-2")
	if ci < 0 || li < 0 || ci > li {
		t.Errorf("findings should be severity-sorted (critical f-1 before low f-2): ci=%d li=%d", ci, li)
	}
}

func TestBuildSystemPrompt_NoFindings(t *testing.T) {
	p := BuildSystemPrompt(types.Asset{Type: types.AssetDomain, Target: "x.com"}, nil)
	if len(p) < minSystemPromptBytes {
		t.Errorf("empty-findings prompt should still clear the guard")
	}
	if !strings.Contains(p, "none") {
		t.Errorf("should note no L1 findings")
	}
}

func TestDigestFindings_SurfacesL15AndBoostsWithinBand(t *testing.T) {
	l1 := []types.Finding{
		// two HIGH findings: the KEV-listed one must rise within the band.
		{ID: "f-plain", Severity: types.SeverityHigh, RuleID: "nuclei::x", Endpoint: "https://x/a", Title: "plain high"},
		{ID: "f-kev", Severity: types.SeverityHigh, RuleID: "nuclei::cve", Endpoint: "https://x/b", Title: "kev high",
			ThreatIntel: &types.ThreatIntel{
				KEV:  &types.KEVStatus{Listed: true},
				EPSS: &types.EPSSScore{Score: 0.94},
			},
			Exploitability: &types.Exploitability{Score: 8},
			CorroboratedBy: []string{"grype", "trivy"},
		},
	}
	lines := digestFindings(l1)
	if len(lines) != 2 {
		t.Fatalf("want 2 digest lines, got %d", len(lines))
	}
	// within-band boost: KEV finding first.
	if !strings.Contains(lines[0], "f-kev") {
		t.Errorf("KEV-listed high should sort before a plain high within the band; got order:\n%v", lines)
	}
	// L1.5 signals surfaced inline.
	for _, want := range []string{"KEV", "EPSS:0.94", "exploit:8", "corrob:2"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("digest line missing L1.5 tag %q: %s", want, lines[0])
		}
	}
	// a bare finding carries no enrichment bracket (the L1.5 suffix is "  […]",
	// distinct from the always-present "[id]" prefix).
	if strings.Contains(lines[1], "  [") {
		t.Errorf("a finding with no L1.5 enrichment should have no enrichment bracket: %s", lines[1])
	}
}
