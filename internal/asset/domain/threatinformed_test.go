package domain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// httpx runs across EVERY discovered subdomain in PlanFanout, so a domain scan fingerprints
// the whole estate at once — the richest observation surface in the product, and the only
// one that was not asking the threat-intel corpus what it had found.
func httpxFinding(host, webserver, tech string) types.Finding {
	return types.Finding{
		RuleID: "httpx::probe", Tool: "httpx", Severity: types.SeverityInfo, Endpoint: host,
		ToolArgs: map[string]string{"webserver": webserver, "tech": tech},
	}
}

func withCorpus(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ti.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", p)
}

func TestPlanEscalation_ProbesExploitedCVEsAgainstObservedSubdomains(t *testing.T) {
	withCorpus(t, `{"CVE-2021-41773":{
	  "kev":{"listed":true,"vendor":"Apache","product":"Apache HTTP Server"},
	  "nuclei_template":"http/cves/2021/CVE-2021-41773.yaml"}}`)

	got := (&Handler{}).PlanEscalation(types.Asset{}, nil, []types.Finding{
		httpxFinding("https://a.acme.test", "Apache/2.4.49", ""),
	})
	if len(got) == 0 {
		t.Fatal("a KEV CVE catalogued against Apache, on a subdomain observed running Apache, " +
			"produced no probe — the intel→discovery loop is not closed for domain")
	}
	var sawNuclei bool
	for _, d := range got {
		if d.Tool.Name() == "nuclei" {
			sawNuclei = true
		}
	}
	if !sawNuclei {
		t.Errorf("dispatches = %+v, want a nuclei probe", got)
	}
}

// Grounded (§10): no corpus, or software nobody catalogues, means no probe. Absence of
// evidence is not a reason to spend a capped budget.
func TestPlanEscalation_NoSignalNoProbe(t *testing.T) {
	withCorpus(t, `{"CVE-2021-41773":{"kev":{"listed":true,"vendor":"Apache","product":"Apache HTTP Server"},
	  "nuclei_template":"x.yaml"}}`)
	if got := (&Handler{}).PlanEscalation(types.Asset{}, nil, []types.Finding{
		httpxFinding("https://a.acme.test", "nginx/1.25.3", ""),
	}); len(got) != 0 {
		t.Errorf("nginx must not be probed for an Apache CVE: %+v", got)
	}
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", "")
	if got := (&Handler{}).PlanEscalation(types.Asset{}, nil, []types.Finding{
		httpxFinding("https://a.acme.test", "Apache/2.4.49", ""),
	}); len(got) != 0 {
		t.Errorf("no corpus must yield no probe: %+v", got)
	}
}

// The honesty half: a CVE we cannot test must be declared, not dropped from the capped plan.
func TestCoverageGaps_DeclaresTheUntestable(t *testing.T) {
	withCorpus(t, `{
	  "CVE-2021-42013":{"kev":{"listed":true,"vendor":"Apache","product":"Apache HTTP Server"}},
	  "CVE-2000-0001":{"epss":{"score":0.9},"nuclei_template":"x.yaml"}}`)
	got := (&Handler{}).CoverageGaps(types.Asset{}, []types.Finding{
		httpxFinding("https://a.acme.test", "Apache/2.4.49", ""),
	})
	if len(got) != 1 {
		t.Fatalf("want the untestable CVE declared, got %+v", got)
	}
	if got[0].Severity != types.SeverityInfo {
		t.Errorf("severity = %q; a check that did not run has no evidence for one", got[0].Severity)
	}
}

// The handler must actually satisfy the interfaces, or the orchestrator never calls either.
func TestHandler_ImplementsTheSeams(t *testing.T) {
	var h any = &Handler{}
	if _, ok := h.(asset.EscalationPlanner); !ok {
		t.Error("domain does not implement EscalationPlanner — the orchestrator will skip it")
	}
	if _, ok := h.(asset.CoverageReporter); !ok {
		t.Error("domain does not implement CoverageReporter — the gaps go nowhere")
	}
}
