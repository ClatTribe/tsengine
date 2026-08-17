package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/threatinformed"
	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
)

func writeWebCorpus(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "threat_intel.json")
	body := `{"CVE-2021-41773":{"kev":{"listed":true,"vendor":"Apache","product":"HTTP Server"},"epss":{"score":0.94}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// WIRING guard for the web asset: PlanEscalation previously DISCARDED its
// findings argument (`_ []types.Finding`), so the httpx technology fingerprint
// could not reach the threat-intel planner at all. This asserts the signal now
// flows handler → common → threatinformed.
func TestPlanEscalation_ThreatInformedFromHttpxFingerprint(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, writeWebCorpus(t))

	// What httpx really reports: the server banner + -tech-detect list.
	findings := []types.Finding{{
		Tool:     "httpx",
		Endpoint: "https://site/",
		ToolArgs: map[string]string{"status": "200", "webserver": "Apache/2.4.49", "tech": "PHP"},
	}}
	out := NewHandler().PlanEscalation(
		types.Asset{Type: types.AssetWebApplication, Target: "https://site/"},
		[]string{"https://site/"}, findings)

	for _, d := range out {
		if d.Tool.Name() == "nuclei" && strings.Contains(d.EscalatedFrom, "threat-intel") {
			if ids, _ := d.Args["id"].(string); !strings.Contains(ids, "CVE-2021-41773") {
				t.Errorf("should probe the KEV CVE for the fingerprinted server, got id=%q", ids)
			}
			return // wired
		}
	}
	t.Fatalf("web escalation must include a threat-informed nuclei probe; got %d dispatches: %+v", len(out), out)
}

// No corpus → unchanged behaviour (no speculative probes).
func TestPlanEscalation_NoCorpusNoThreatInformedProbe(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, "")
	findings := []types.Finding{{
		Tool: "httpx", Endpoint: "https://site/",
		ToolArgs: map[string]string{"webserver": "Apache/2.4.49"},
	}}
	for _, d := range NewHandler().PlanEscalation(
		types.Asset{Type: types.AssetWebApplication, Target: "https://site/"},
		[]string{"https://site/"}, findings) {
		if strings.Contains(d.EscalatedFrom, "threat-intel") {
			t.Fatalf("no corpus configured must yield no threat-informed dispatch, got %+v", d)
		}
	}
}
