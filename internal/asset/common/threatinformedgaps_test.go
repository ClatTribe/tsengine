package common

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// writeGapCorpus writes a threat-intel corpus and points the env var at it.
func writeGapCorpus(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ti.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", p)
}

// An nmap/httpx finding carrying the product observation the planner reads.
func observedApache() []types.Finding {
	return []types.Finding{{
		ID: "f1", RuleID: "nmap::service", Tool: "nmap", Severity: types.SeverityInfo,
		Endpoint: "http://t.test", ToolArgs: map[string]string{"product": "Apache httpd", "version": "2.4.49"},
	}}
}

// The gap must be DECLARED. A KEV CVE against software we can see, which we have no way to
// check, is exactly the thing an operator must not have to infer from an absence.
func TestThreatInformedGaps_DeclaresTheUntestable(t *testing.T) {
	writeGapCorpus(t, `{
	  "CVE-2021-41773":{"kev":{"listed":true,"product":"Apache HTTP Server"},"nuclei_template":"http/cves/2021/CVE-2021-41773.yaml"},
	  "CVE-2021-42013":{"kev":{"listed":true,"product":"Apache HTTP Server"}}
	}`)
	got := ThreatInformedGaps(observedApache())
	if len(got) != 1 {
		t.Fatalf("want 1 gap finding, got %d: %+v", len(got), got)
	}
	g := got[0]
	if !strings.Contains(g.ToolArgs["cves"], "CVE-2021-42013") {
		t.Errorf("the untestable CVE must be named: %v", g.ToolArgs)
	}
	if strings.Contains(g.ToolArgs["cves"], "CVE-2021-41773") {
		t.Errorf("a CVE we DID test must not be reported as a gap: %v", g.ToolArgs)
	}
}

// A coverage gap asserts an absence of TESTING. Assigning it a real severity would
// manufacture a vulnerability out of a check that did not run — the same overclaim as a
// green tick on an unscanned scope, pointed the other way.
func TestThreatInformedGaps_IsInformationalNotAVulnClaim(t *testing.T) {
	writeGapCorpus(t, `{"CVE-2021-42013":{"kev":{"listed":true,"product":"Apache HTTP Server"}},
	                 "CVE-2000-0001":{"epss":{"score":0.9},"nuclei_template":"x.yaml"}}`)
	got := ThreatInformedGaps(observedApache())
	if len(got) != 1 {
		t.Fatalf("want 1 gap, got %d", len(got))
	}
	if got[0].Severity != types.SeverityInfo {
		t.Errorf("severity = %q; a check that did not run has no evidence for one", got[0].Severity)
	}
	// Matching is on PRODUCT, not version, so the text must not claim the target is affected.
	d := strings.ToLower(got[0].Description)
	if !strings.Contains(d, "coverage gap, not a vulnerability") {
		t.Error("the description must say plainly that this is not a vulnerability claim")
	}
	if !strings.Contains(d, "product") || !strings.Contains(d, "version") {
		t.Error("the description must state that the match is on product rather than version")
	}
}

// The common case is nothing to declare, and reaching it must be cheap and silent.
func TestThreatInformedGaps_NothingToDeclare(t *testing.T) {
	writeGapCorpus(t, `{"CVE-2021-41773":{"kev":{"listed":true,"product":"Apache HTTP Server"},"nuclei_template":"x.yaml"}}`)
	if got := ThreatInformedGaps(observedApache()); len(got) != 0 {
		t.Errorf("everything matched was testable; want no gap, got %+v", got)
	}
}

// No corpus, or nothing observed, must be a graceful no-op — a coverage claim needs
// evidence just as a finding does.
func TestThreatInformedGaps_NoCorpusOrNoObservationIsSilent(t *testing.T) {
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", "")
	if got := ThreatInformedGaps(observedApache()); got != nil {
		t.Errorf("no corpus must declare nothing, got %+v", got)
	}
	writeGapCorpus(t, `{"CVE-2021-42013":{"kev":{"listed":true,"product":"Apache HTTP Server"}}}`)
	if got := ThreatInformedGaps(nil); got != nil {
		t.Errorf("no observation must declare nothing, got %+v", got)
	}
}

// A corpus that carries no template data at all is an OLDER corpus, not proof that
// nothing is testable. Declaring every matched CVE a gap would turn a stale feed into a
// wall of alarming informational findings.
func TestThreatInformedGaps_CorpusWithoutTemplateDataDeclaresNothing(t *testing.T) {
	writeGapCorpus(t, `{"CVE-2021-41773":{"kev":{"listed":true,"product":"Apache HTTP Server"}},
	                 "CVE-2021-42013":{"kev":{"listed":true,"product":"Apache HTTP Server"}}}`)
	if got := ThreatInformedGaps(observedApache()); len(got) != 0 {
		t.Errorf("a corpus with no availability data knows of no gaps; got %+v", got)
	}
}

// The finding has to survive the dashboard contract — it is emitted like any other.
func TestThreatInformedGaps_SerializesCleanly(t *testing.T) {
	writeGapCorpus(t, `{"CVE-2021-42013":{"kev":{"listed":true,"product":"Apache HTTP Server"}},
	                 "CVE-2000-0001":{"epss":{"score":0.9},"nuclei_template":"x.yaml"}}`)
	got := ThreatInformedGaps(observedApache())
	if len(got) == 0 {
		t.Fatal("want a gap")
	}
	if _, err := json.Marshal(got[0]); err != nil {
		t.Fatalf("gap finding does not serialize: %v", err)
	}
	if got[0].Endpoint == "" || got[0].RuleID == "" {
		t.Errorf("a finding with no endpoint or rule cannot be deduped or tracked: %+v", got[0])
	}
}
