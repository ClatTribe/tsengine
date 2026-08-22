package grc

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func kevFinding() types.Finding {
	return types.Finding{
		ID: "f-1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical,
		Title: "Log4Shell", CWE: []string{"CWE-94"}, VerificationStatus: "corroborated",
		DiscoveredAt: time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC),
		ThreatIntel: &types.ThreatIntel{
			CVSS: 10.0, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			KEV: &types.KEVStatus{Listed: true},
		},
	}
}

// THE POINT OF THE FEATURE. "0 actively exploited" against a four-month-old snapshot and against
// today's feed are different claims, and the report rendered them identically.
func TestIntelCaveat_StaleCorpusQualifiesTheExploitationClaims(t *testing.T) {
	p := &IntelProvenance{AgeDays: 113, Stale: true, Embedded: true}
	c := p.IntelCaveat()
	for _, want := range []string{"not current", "113 days", "CISA KEV", "not evidence that none exist"} {
		if !strings.Contains(c, want) {
			t.Errorf("caveat missing %q — got %q", want, c)
		}
	}
}

// A current corpus must produce NO caveat: a warning that is always present is one nobody reads.
func TestIntelCaveat_CurrentCorpusIsSilent(t *testing.T) {
	if c := (&IntelProvenance{AgeDays: 2}).IntelCaveat(); c != "" {
		t.Errorf("a fresh corpus should carry no caveat, got %q", c)
	}
	if c := (*IntelProvenance)(nil).IntelCaveat(); c != "" {
		t.Errorf("unknown provenance should not fabricate a caveat, got %q", c)
	}
}

// The caveat has to appear where the claim is made. BOTH media, and the exec one-pager too — that
// is the page a customer forwards and quotes.
func TestReports_CarryTheIntelCaveatInEveryMedium(t *testing.T) {
	r := ReportFromFindings([]types.Finding{kevFinding()}, []string{"img"}, "Acme", time.Now().UTC(), nil)
	r.Intel = &IntelProvenance{Version: "ti-snapshot-2026-05-01", AgeDays: 113, Stale: true, Embedded: true,
		KEVAsOf: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}

	for name, out := range map[string]string{
		"full markdown":  RenderVAPTMarkdown(r),
		"exec markdown":  RenderVAPTExecMarkdown(r),
		"print/PDF html": RenderVAPTHTML(r),
	} {
		if !strings.Contains(out, "not current") {
			t.Errorf("%s: intel caveat missing — the KEV figure is unqualified", name)
		}
	}
	// The provenance line names what was actually used (full report + HTML methodology section).
	md := RenderVAPTMarkdown(r)
	for _, want := range []string{"ti-snapshot-2026-05-01", "CISA KEV as of 2026-05-01", "engine-embedded snapshot"} {
		if !strings.Contains(md, want) {
			t.Errorf("provenance line missing %q", want)
		}
	}
}

// A CVSS vector is the actionable half of the score and unreadable to most recipients.
func TestCVSSVectorProse_DecodesTheStandardMetrics(t *testing.T) {
	got := cvssVectorProse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
	for _, want := range []string{"Reachable over the network", "low attack complexity",
		"no privileges needed", "no user interaction", "scope change",
		"high impact to confidentiality, integrity and availability"} {
		if !strings.Contains(got, want) {
			t.Errorf("prose missing %q — got %q", want, got)
		}
	}
	// The opposite end of every axis must read as its opposite, or the sentence is decorative.
	local := cvssVectorProse("AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
	// Case-insensitive: the first phrase is sentence-initial and therefore capitalised.
	lower := strings.ToLower(local)
	for _, want := range []string{"requires local access", "high attack complexity",
		"needs high privileges", "requires user interaction"} {
		if !strings.Contains(lower, want) {
			t.Errorf("low-risk vector prose missing %q — got %q", want, local)
		}
	}
	// Unchanged scope and non-High impacts are deliberately not narrated.
	if strings.Contains(lower, "scope") || strings.Contains(lower, "impact") {
		t.Errorf("unchanged scope / low impact should not be narrated: %q", local)
	}
}

// An unrecognised metric must SHORTEN the sentence, never produce a confident wrong one.
func TestCVSSVectorProse_SkipsWhatItDoesNotKnow(t *testing.T) {
	if got := cvssVectorProse("AV:N/XX:Q/AC:Z"); got != "Reachable over the network." {
		t.Errorf("unknown metric/value should be skipped, got %q", got)
	}
	for _, junk := range []string{"", "not-a-vector", "AV:", ":N"} {
		if got := cvssVectorProse(junk); got != "" {
			t.Errorf("unparseable vector %q should yield nothing, got %q", junk, got)
		}
	}
}

// "How long has this been open?" is a question an auditor asks and the report could not answer.
func TestReports_RenderFirstObserved(t *testing.T) {
	r := ReportFromFindings([]types.Finding{kevFinding()}, []string{"img"}, "Acme", time.Now().UTC(), nil)
	if r.Findings[0].DiscoveredAt.IsZero() {
		t.Fatal("DiscoveredAt not carried onto the report finding")
	}
	if md := RenderVAPTMarkdown(r); !strings.Contains(md, "**First observed:** 2026-03-04") {
		t.Error("markdown missing first-observed date")
	}
	if h := RenderVAPTHTML(r); !strings.Contains(h, "First observed:</b> 2026-03-04") {
		t.Error("html missing first-observed date")
	}
	// A finding with no recorded date must render no date rather than the zero time.
	bare := ReportFromFindings([]types.Finding{{ID: "f-2", RuleID: "r", Tool: "t",
		Severity: types.SeverityLow, Title: "x"}}, []string{"img"}, "Acme", time.Now().UTC(), nil)
	if strings.Contains(RenderVAPTMarkdown(bare), "First observed") {
		t.Error("a finding with no date must not render one")
	}
	if strings.Contains(RenderVAPTHTML(bare), "0001-01-01") {
		t.Error("zero time leaked into the html report")
	}
}
