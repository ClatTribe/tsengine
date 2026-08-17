package ip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/threatinformed"
	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
)

// WIRING guard. The unit tests for internal/threatinformed and for
// common.ThreatInformedEscalation prove the planner and the glue work; they do
// NOT prove this handler actually CALLS the glue. That gap is exactly how the
// api asset silently produced zero findings for months (a correct component,
// never reached in production), so the wiring gets its own test.
func TestPlanEscalation_ThreatInformedTargetsObservedProduct(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "threat_intel.json")
	// CVE-2021-41773 is KEV-listed against Apache HTTP Server.
	body := `{"CVE-2021-41773":{"kev":{"listed":true,"vendor":"Apache","product":"HTTP Server"},"epss":{"score":0.94}}}`
	if err := os.WriteFile(corpus, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(threatinformed.CorpusEnv, corpus)

	// What nmap really reports for a fingerprinted service.
	findings := []types.Finding{{
		Tool:     "nmap",
		Endpoint: "10.0.0.5:80",
		ToolArgs: map[string]string{"product": "Apache httpd", "version": "2.4.49", "port": "80"},
	}}

	out := h().PlanEscalation(types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.5"}, []string{"10.0.0.5:80"}, findings)

	var found bool
	for _, d := range out {
		if d.Tool.Name() == "nuclei" && strings.Contains(d.EscalatedFrom, "threat-intel") {
			found = true
			if ids, _ := d.Args["id"].(string); !strings.Contains(ids, "CVE-2021-41773") {
				t.Errorf("threat-informed dispatch should probe the KEV CVE, got id=%q", ids)
			}
		}
	}
	if !found {
		t.Fatalf("ip escalation must include a threat-informed nuclei probe; got %d dispatches: %+v", len(out), out)
	}
}

// Default (no corpus configured) must stay a pure no-op, so an operator without
// a refreshed corpus sees exactly today's behaviour.
func TestPlanEscalation_NoCorpusNoThreatInformedDispatch(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, "")
	findings := []types.Finding{{
		Tool: "nmap", Endpoint: "10.0.0.5:80",
		ToolArgs: map[string]string{"product": "Apache httpd", "version": "2.4.49"},
	}}
	for _, d := range h().PlanEscalation(types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.5"}, []string{"10.0.0.5:80"}, findings) {
		if strings.Contains(d.EscalatedFrom, "threat-intel") {
			t.Fatalf("no corpus configured must yield no threat-informed dispatch, got %+v", d)
		}
	}
}

func h() *Handler { return NewHandler() }
