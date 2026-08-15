package platformapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// The properties that decide whether a log platform can actually consume this. Getting NDJSON subtly
// wrong is worse than not offering it, because the ingest usually succeeds and the data is useless.

// ONE EVENT PER LINE, and each line must parse on its own. Handed a wrapped array, Splunk and
// Datadog either reject it or swallow the whole thing as one enormous event — which looks like it
// worked, which is the bad part.
func TestSIEMEvent_EachLineParsesAlone(t *testing.T) {
	fs := []types.Finding{
		{ID: "f1", RuleID: "trivy::CVE-2026-1234", Tool: "trivy", Severity: types.SeverityHigh, Title: "vuln one"},
		{ID: "f2", RuleID: "gitleaks::aws-key", Tool: "gitleaks", Severity: types.SeverityCritical, Title: "leaked key"},
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, f := range fs {
		_ = enc.Encode(siemEventFor("t1", f))
	}
	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines for 2 findings", len(lines))
	}
	for i, ln := range lines {
		var got siemEvent
		if err := json.Unmarshal([]byte(ln), &got); err != nil {
			t.Fatalf("line %d does not parse on its own: %v", i+1, err)
		}
		if got.Source != "tensorshield" {
			t.Errorf("line %d has no source field, so a SIEM rule cannot scope to our events", i+1)
		}
	}
}

// A zero timestamp must not ship as year 1. A log platform either rejects it or files the event in
// 0001, where nobody will ever look at it again.
func TestSIEMEvent_ZeroTimeIsNotYearOne(t *testing.T) {
	e := siemEventFor("t1", types.Finding{ID: "f", Title: "x"})
	if strings.HasPrefix(e.Time, "0001") {
		t.Fatalf("a finding with no timestamp exported as %q", e.Time)
	}
	if _, err := time.Parse(time.RFC3339, e.Time); err != nil {
		t.Errorf("time is not RFC3339: %q", e.Time)
	}
}

// A real timestamp must survive untouched — the fallback must not overwrite good data.
func TestSIEMEvent_RealTimeIsPreserved(t *testing.T) {
	when := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	e := siemEventFor("t1", types.Finding{ID: "f", DiscoveredAt: when})
	if !strings.HasPrefix(e.Time, "2026-03-04T05:06:07") {
		t.Errorf("the discovery time was replaced: %q", e.Time)
	}
}

// The CVE comes from the same place the enrichment chain looks. A second notion of "has a CVE" would
// let the export and the enrichment disagree about the same finding.
func TestSIEMEvent_CVEMatchesTheEnrichmentChain(t *testing.T) {
	if got := siemEventFor("t", types.Finding{RuleID: "trivy::CVE-2026-9999"}).CVE; got != "CVE-2026-9999" {
		t.Errorf("CVE from rule id = %q", got)
	}
	if got := siemEventFor("t", types.Finding{Title: "Fix CVE-2025-0001 in libfoo"}).CVE; got != "CVE-2025-0001" {
		t.Errorf("CVE from title = %q", got)
	}
	// And no CVE means the field is absent, not blank — a SIEM rule matching cve="" would fire on
	// every non-CVE finding.
	e := siemEventFor("t", types.Finding{RuleID: "gitleaks::aws-key", Title: "leaked key"})
	if e.CVE != "" {
		t.Errorf("invented a CVE: %q", e.CVE)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), `"cve"`) {
		t.Error("an empty CVE was serialized rather than omitted")
	}
}

// The event must be FLAT. A nested object is where SIEM field extraction goes wrong — a search for
// severity has to know whether it is `severity` or `finding.severity`.
func TestSIEMEvent_IsFlat(t *testing.T) {
	b, _ := json.Marshal(siemEventFor("t1", types.Finding{
		ID: "f", CWE: []string{"CWE-79", "CWE-89"}, Severity: types.SeverityHigh,
	}))
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	for k, v := range generic {
		switch v.(type) {
		case map[string]any, []any:
			t.Errorf("field %q is nested (%T) — SIEM field extraction will not find it reliably", k, v)
		}
	}
	// A CWE list specifically must be joined, not an array.
	if generic["cwe"] != "CWE-79,CWE-89" {
		t.Errorf("cwe = %v, want a joined string", generic["cwe"])
	}
}

// KEV and EPSS ride along, because they are what an on-call engineer filters on and re-deriving them
// on the SIEM side would need the whole threat-intel corpus.
func TestSIEMEvent_CarriesKEVAndEPSS(t *testing.T) {
	f := types.Finding{
		ID: "f", RuleID: "trivy::CVE-2026-1", ThreatIntel: &types.ThreatIntel{
			KEV: &types.KEVStatus{Listed: true}, EPSS: &types.EPSSScore{Score: 0.87},
		},
	}
	e := siemEventFor("t", f)
	if !e.KEV {
		t.Error("a KEV-listed finding exported kev=false")
	}
	if e.EPSS < 0.86 || e.EPSS > 0.88 {
		t.Errorf("epss = %v, want 0.87", e.EPSS)
	}
	// Absent threat intel must not fabricate a score.
	plain := siemEventFor("t", types.Finding{ID: "g"})
	if plain.KEV || plain.EPSS != 0 {
		t.Errorf("a finding with no threat intel exported kev=%v epss=%v", plain.KEV, plain.EPSS)
	}
}
