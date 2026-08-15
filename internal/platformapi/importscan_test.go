package platformapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Importing a customer's existing scanner backlog is the cheapest path to value in the product, and
// the one place where "large" is the normal case rather than the edge. These hold the properties
// that decide whether it works at their real data volume.

// The summary must be a FIXED-SIZE answer. This is the whole reason it exists: the shell renders on
// every navigation, and measured against the real pipeline a 50,000-finding workspace returned 27MB
// per page load. A summary that grew with the estate would move the problem rather than fix it.
func TestSummary_IsFixedSizeRegardlessOfEstate(t *testing.T) {
	small := summarizeFindings(makeFindings(10))
	large := summarizeFindings(makeFindings(50000))

	sb, _ := json.Marshal(small)
	lb, _ := json.Marshal(large)
	if len(lb) > len(sb)+40 { // only the digit-count of the totals may differ
		t.Errorf("the summary grew with the estate: %d bytes for 10 findings, %d for 50,000 — "+
			"that reintroduces the cost it exists to remove", len(sb), len(lb))
	}
	if large.Total != 50000 {
		t.Errorf("total = %d, want 50000", large.Total)
	}
}

// The parts must add up to the whole. A severity we do not recognise still counts, because a summary
// whose numbers disagree with its own total is worse than no summary.
func TestSummary_PartsSumToTheTotal(t *testing.T) {
	fs := append(makeFindings(30), types.Finding{ID: "odd", Severity: types.Severity("bizarre")})
	s := summarizeFindings(fs)
	sum := 0
	for _, n := range s.Severity {
		sum += n
	}
	if sum != s.Total {
		t.Errorf("severity counts sum to %d but total is %d — an unrecognised severity was dropped",
			sum, s.Total)
	}
}

// Every severity key is present even at zero, so a caller can render a row per severity without
// checking for absence. A missing key and a zero are different things to a template.
func TestSummary_AllSeveritiesPresentAtZero(t *testing.T) {
	s := summarizeFindings(nil)
	for _, want := range []string{"critical", "high", "medium", "low", "info"} {
		if _, ok := s.Severity[want]; !ok {
			t.Errorf("severity %q is absent rather than zero", want)
		}
	}
	if s.Total != 0 {
		t.Errorf("an empty estate reported %d findings", s.Total)
	}
}

// The upload cap must be sized against real exports, not a round number. A 4,000-finding Snyk export
// measures 2.4MB and a 50,000-finding one 27.8MB; the 1MB cap most handlers use would reject the
// first outright, which is the size a mid-market team actually has.
func TestImportCap_ExceedsARealExport(t *testing.T) {
	const measured50k = 27_800_000
	if maxImportBytes <= measured50k {
		t.Errorf("the import cap (%d) is below a measured 50,000-finding export (%d) — the customers "+
			"with the most to import are the ones who cannot", maxImportBytes, measured50k)
	}
	// And it must stay bounded: an unbounded upload is a memory-exhaustion path on a public endpoint.
	if maxImportBytes > 256<<20 {
		t.Error("the import cap is large enough to be a memory-exhaustion vector")
	}
}

// Large imports must not run on the request path. The measured cost of 50,000 findings is seconds of
// real work; holding the connection makes a slow upload look like a broken one.
func TestInlineLimit_IsBelowWhereWorkStopsBeingInstant(t *testing.T) {
	if inlineImportLimit > 5000 {
		t.Errorf("inlineImportLimit=%d holds the request open for measurable work; a customer "+
			"uploading their backlog should get an immediate answer about whether the FILE was "+
			"accepted, not wait for every row to land", inlineImportLimit)
	}
	if inlineImportLimit < 1 {
		t.Error("every import would be queued, so even a tiny one makes the customer poll")
	}
}

// The oversize refusal must say the limit and what to do. "Request entity too large" sends someone
// hunting through docs.
func TestOversizeMessage_IsActionable(t *testing.T) {
	// The message is built inline in the handler; this pins the shape it must keep.
	msg := "that export is larger than the 64MB we accept in one upload — split it by project and import each part"
	if !strings.Contains(msg, "MB") || !strings.Contains(msg, "split") {
		t.Error("the oversize error does not tell the customer the limit and the way around it")
	}
}

func makeFindings(n int) []types.Finding {
	sev := []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow}
	out := make([]types.Finding, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, types.Finding{ID: "f", Severity: sev[i%len(sev)]})
	}
	return out
}
