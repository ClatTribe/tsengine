package samplereport

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The /sample-report page renders a hand-written PREVIEW (frontend/lib/sample-report.ts) beside
// a link to the report this package GENERATES. Nothing connected the two, and they had drifted:
// the page showed "Acme (sample) · acme-sample.com · 6 findings" while the download said
// "Example Corp · 4 findings". A prospect comparing them sees two different companies on the
// one asset whose whole argument is that our numbers survive being checked.
//
// This is the same cross-file discipline internal/uicheck applies to the app surface: a Go test
// reading the frontend source, because the defect lives in the space BETWEEN the two halves
// where neither side's own tests can see it.
//
// It deliberately checks IDENTITY and COUNTS, not prose — the preview is allowed to describe
// findings in its own words, but it may not describe a different company or a different number
// of them.
func TestPagePreviewMatchesTheGeneratedReport(t *testing.T) {
	path := filepath.Join("..", "..", "frontend", "lib", "sample-report.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		// §14.2 rule 6: a guard that cannot see its subject FAILS. Skipping here would go green
		// at exactly the moment the file was renamed or moved — when it is least verified.
		t.Fatalf("cannot read the page's sample data at %s: %v", path, err)
	}
	src := string(raw)
	// Comments explain the rules and legitimately quote the names those rules forbid, so the
	// checks below run over CODE only. Scanning them too made the guard fail on its own
	// documentation, which is the fastest way to get a guard deleted.
	var code strings.Builder
	for _, ln := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "//") {
			continue
		}
		code.WriteString(ln)
		code.WriteString("\n")
	}
	src = code.String()

	// Identity. The page must name the same subject as the document it links to.
	if !strings.Contains(src, `org: "`+Name+`"`) {
		t.Errorf("frontend/lib/sample-report.ts does not set org to %q — the page and the "+
			"downloadable report would name different companies", Name)
	}

	// Reserved domains, on the page too. The generator is guarded by
	// TestScopeNamesOnlyReservedDocumentationTargets; the page had no such check and was using
	// acme-sample.com, which anybody can register.
	for _, bad := range regexp.MustCompile(`[a-z0-9-]+\.(com|io|net|org|dev|app)`).FindAllString(src, -1) {
		switch {
		case strings.HasSuffix(bad, "example.com"),
			strings.HasSuffix(bad, "example.org"),
			strings.HasSuffix(bad, "example.net"):
		default:
			t.Errorf("the page names %q — a published sample must use RFC 2606 reserved names "+
				"so it cannot be read as an assessment of a real party", bad)
		}
	}

	// Counts. The preview advertises a severity mix; it must be the mix the report contains.
	want := map[string]int{}
	for _, f := range Findings(time.Now().UTC()) {
		want[string(f.Severity)]++
	}
	got := map[string]int{}
	for _, m := range regexp.MustCompile(`severity: "(critical|high|medium|low)",`).FindAllStringSubmatch(src, -1) {
		got[m[1]]++
	}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if got[sev] != want[sev] {
			t.Errorf("%s: page preview has %d, generated report has %d", sev, got[sev], want[sev])
		}
	}
	total := 0
	for _, n := range got {
		total += n
	}
	if total != len(Findings(time.Now().UTC())) {
		t.Errorf("page preview lists %d findings, the report generates %d", total, len(Findings(time.Now().UTC())))
	}
}
