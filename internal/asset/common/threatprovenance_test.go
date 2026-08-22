package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A probe selected on CISA's SSVC assessment must not be labelled KEV/EPSS-targeted.
//
// The provenance string is what §5.3 keeps for logging and audit. It named a fixed pair of signals
// regardless of what actually chose the CVE, which became wrong the moment SSVC joined the gate: a
// probe grounded in "CISA says exploitation is ACTIVE" was reported as grounded in two signals that
// had said nothing about it. A label that misnames why we spent a probe is worse than a vague one.
func TestThreatInformedEscalation_ProvenanceNamesTheRealSignal(t *testing.T) {
	corpus := filepath.Join(t.TempDir(), "ti.json")
	// SSVC-active only: NOT on KEV, no EPSS, no public exploit.
	body := `{"CVE-2024-0001":{"ssvc":{"exploitation":"active","automatable":"yes"},` +
		`"kev":{"listed":false,"product":"Apache HTTP Server"},` +
		`"nuclei_template":"http/cves/2024/CVE-2024-0001.yaml"}}`
	if err := os.WriteFile(corpus, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", corpus)

	got := ThreatInformedEscalation([]types.Finding{{
		RuleID: "nmap::service", Tool: "nmap", Endpoint: "http://t.test",
		ToolArgs: map[string]string{"product": "Apache HTTP Server", "version": "2.4.49"},
	}})
	if len(got) == 0 {
		// NOT a skip. If the gate stops selecting this CVE the label assertions below never run, and
		// the test reports green while checking nothing — §14.2 rule 6, which I wrote earlier today
		// and then reproduced here.
		t.Fatal("no probe was planned for a CVE CISA assesses as actively exploited — either the gate " +
			"regressed or this fixture no longer exercises it; both need looking at, not skipping")
	}
	prov := got[0].EscalatedFrom
	if strings.Contains(prov, "KEV/EPSS-targeted") {
		t.Errorf("the old fixed label survived: %q", prov)
	}
	if !strings.Contains(prov, "SSVC-active") {
		t.Errorf("a probe selected on SSVC must say so: %q", prov)
	}
}

// The formatter itself, without the corpus plumbing: strongest signal first, and a batch we cannot
// explain is not given a reason we invented.
func TestThreatProvenance_NamesSignalsStrongestFirst(t *testing.T) {
	got := threatProvenance(5, 2, 1, 1, 1)
	if !strings.Contains(got, "2 KEV") || !strings.Contains(got, "1 SSVC-active") {
		t.Errorf("signals not named: %q", got)
	}
	if strings.Index(got, "KEV") > strings.Index(got, "EPSS") {
		t.Errorf("KEV must lead EPSS — they are not interchangeable grounds: %q", got)
	}
	if unexplained := threatProvenance(3, 0, 0, 0, 0); !strings.Contains(unexplained, "not recorded") {
		t.Errorf("a batch with no recorded signal must say so rather than claim one: %q", unexplained)
	}
}
