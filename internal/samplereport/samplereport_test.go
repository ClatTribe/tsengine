package samplereport

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
)

var at = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// The whole premise of this asset is that the product generates it. These are fields NOTHING
// in samplereport.go writes — grc.ReportFromFindings derives every one of them from the raw
// findings. Hand-write the report and they all go to zero.
func TestReportIsProducedByTheProductsOwnGenerator(t *testing.T) {
	r := Report(at)

	if r.Summary.ExploitProven != 1 {
		t.Errorf("ExploitProven = %d, want 1 — only grc's extractPoC sets this; a hand-built "+
			"report would not have it", r.Summary.ExploitProven)
	}
	if r.Summary.KEV != 1 {
		t.Errorf("KEV = %d, want 1 (derived from ThreatIntel.KEV)", r.Summary.KEV)
	}
	if r.Summary.Ransomware != 1 {
		t.Errorf("Ransomware = %d, want 1 (derived from KEV.Ransomware)", r.Summary.Ransomware)
	}
	if r.Summary.Automatable != 1 {
		t.Errorf("Automatable = %d, want 1 (derived from SSVC.Automatable)", r.Summary.Automatable)
	}
	if r.Summary.Total != len(Findings(at)) {
		t.Errorf("Total = %d, want %d", r.Summary.Total, len(Findings(at)))
	}
	// The PoC must be lifted OUT of the description into its own field — that separation is
	// what lets the report render proof as proof instead of burying it in prose.
	var proven *grc.VAPTFinding
	for i := range r.Findings {
		if r.Findings[i].PoC != "" {
			proven = &r.Findings[i]
		}
	}
	if proven == nil {
		t.Fatal("no finding carries an extracted PoC — the exploitation-proven tier is the " +
			"single thing this report exists to show")
	}
	if strings.Contains(proven.Description, "[Exploitation PoC") {
		t.Error("the PoC marker is still in the description body — it was not extracted")
	}
}

// Worst-first ordering is the generator's, not ours. A reader scans the top of the report.
func TestFindingsAreOrderedWorstFirst(t *testing.T) {
	r := Report(at)
	if len(r.Findings) < 2 {
		t.Fatalf("only %d findings", len(r.Findings))
	}
	if r.Findings[0].Severity != "critical" {
		t.Errorf("first finding severity = %q, want critical", r.Findings[0].Severity)
	}
	last := r.Findings[len(r.Findings)-1]
	if last.Severity == "critical" {
		t.Error("a critical sorted last — ordering is not being applied")
	}
}

// THE ADMISSIONS. A sample built only from proven wins would misrepresent the product in the
// flattering direction — the exact failure the engine exists to prevent, in our own shop
// window. Each of these is a separate claim and none may quietly disappear.
func TestSampleShowsWhatWasNotProvenAndNotChecked(t *testing.T) {
	r := Report(at)

	if len(r.Untested) == 0 {
		t.Error("Untested is empty — the sample no longer shows that unscanned scope is " +
			"reported rather than silently counted as clean")
	}
	if len(r.PartiallyAssessed) == 0 {
		t.Error("PartiallyAssessed is empty — the sample no longer shows the distinction " +
			"between 'we looked and it was fine' and 'a tool dropped out'")
	}
	// Untested and PartiallyAssessed are DIFFERENT claims; a sample that used one target for
	// both would let a reader think they are the same thing.
	for _, u := range r.Untested {
		for _, p := range r.PartiallyAssessed {
			if u == p {
				t.Errorf("%q is listed as both untested and partially assessed", u)
			}
		}
	}
	var unconfirmed int
	for _, f := range r.Findings {
		if f.Unconfirmed {
			unconfirmed++
		}
	}
	if unconfirmed == 0 {
		t.Error("every finding is confirmed — the sample no longer shows that we distinguish " +
			"what we proved from what we matched")
	}
	if unconfirmed == len(r.Findings) {
		t.Error("nothing is confirmed — the sample no longer shows the proven tier")
	}
}

// The subject must be structurally unmistakable. A sample report listing exploitable
// vulnerabilities against a plausible real company is a fabricated assessment of a party that
// never consented to one, and it is damaging precisely because it looks real. RFC 2606
// reserves these names so documentation cannot do that by accident.
func TestScopeNamesOnlyReservedDocumentationTargets(t *testing.T) {
	r := Report(at)
	if len(r.Scope) == 0 {
		t.Fatal("empty scope")
	}
	for _, s := range r.Scope {
		host := s
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.IndexAny(host, "/:"); i >= 0 {
			host = host[:i]
		}
		switch {
		case strings.HasSuffix(host, "example.com"),
			strings.HasSuffix(host, "example.org"),
			strings.HasSuffix(host, "example.net"),
			// A repo path and a cloud account id name no resolvable host; they are scoped by
			// the obviously-fictional org/account below.
			strings.HasPrefix(s, "github.com/example-corp/"),
			strings.HasPrefix(s, "aws:1234567890"):
		default:
			t.Errorf("scope target %q is not an RFC 2606 reserved / obviously-fictional name — "+
				"a published sample must not name a party that could be real", s)
		}
	}
	if !strings.Contains(strings.ToLower(Name), "sample") {
		t.Errorf("Name = %q — the reader must be told this is a sample", Name)
	}
}

// Deterministic: same input instant, same document. Nothing here may read the clock, or two
// renders of the "same" sample would differ and the asset could not be cached or diffed.
func TestReportIsDeterministic(t *testing.T) {
	a, b := grc.RenderVAPTMarkdown(Report(at)), grc.RenderVAPTMarkdown(Report(at))
	if a != b {
		t.Error("two renders at the same instant differ — something reads the clock")
	}
	if c := grc.RenderVAPTMarkdown(Report(at.Add(time.Hour))); c == a {
		t.Error("renders at different instants are identical — the timestamps are not real")
	}
}

// It has to actually render in both formats the endpoint serves.
func TestRendersInBothPublishedFormats(t *testing.T) {
	r := Report(at)
	md := grc.RenderVAPTMarkdown(r)
	html := grc.RenderVAPTHTML(r)
	for _, want := range []string{"Example Corp", "SQL injection"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if len(md) < 500 || len(html) < 500 {
		t.Errorf("render suspiciously short: md=%d html=%d", len(md), len(html))
	}
}
