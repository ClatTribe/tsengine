package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei" // register the probe tool
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The api asset must FINGERPRINT the server, because threat-informed discovery is grounded on what
// the target really runs.
//
// Without a fingerprinting anchor, ObservationsFromFindings returns empty and no CVE probe can ever
// be grounded — the engine could know a CVE is exploited in the wild against nginx, be pointed at an
// API served by that nginx, and never look for it. CLAUDE.md §7.1 recorded the asset as deliberately
// unwired for that reason and named this as the fix.
func TestAPIAnchorsIncludeAFingerprinter(t *testing.T) {
	var found bool
	for _, n := range anchorNames {
		if n == "httpx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no fingerprinting anchor in %v — threat-informed probing on this asset cannot be "+
			"grounded, because nothing observes what the target runs", anchorNames)
	}
}

// And the escalation must consume it. An anchor that fingerprints while nothing reads the
// observation would be the upstream half without the downstream one.
func TestAPIEscalationConsultsThreatIntel(t *testing.T) {
	h := NewHandler()
	// A finding in the shape httpx emits: the product is in ToolArgs, structured.
	findings := []types.Finding{{
		RuleID:   "httpx::probe",
		Tool:     "httpx",
		Endpoint: "https://api.example.com",
		ToolArgs: map[string]string{"webserver": "Apache/2.4.49", "status": "200"},
	}}
	// With no corpus configured this is a no-op by design (§10: no intel, no probe) — the property
	// under test is that the call is WIRED, which a panic or a compile failure would catch and a
	// silent omission would not. The kiterunner empty-surface dispatch still comes through.
	got := h.PlanEscalation(types.Asset{Type: types.AssetAPI, Target: "https://api.example.com"}, nil, findings)
	for _, d := range got {
		if strings.Contains(d.EscalatedFrom, "threat") && d.Tool == nil {
			t.Error("a threat-informed dispatch carried no tool")
		}
	}
}

// END TO END: a real corpus, a real httpx observation, and a probe that actually gets planned.
//
// The two tests above prove the anchor is declared and the call is wired. Neither proves the thing
// that matters — that pointing this asset at a server running software with a KEV-listed CVE now
// produces a probe for it, which is the whole point of the fingerprinter.
func TestAPIThreatInformedProbeIsPlannedFromAnHTTPXObservation(t *testing.T) {
	corpus := filepath.Join(t.TempDir(), "ti.json")
	// One KEV-listed CVE against the product httpx will report, with a nuclei template so it is
	// testable rather than merely known.
	body := `{"CVE-2021-41773":{"kev":{"listed":true,"product":"Apache HTTP Server"},` +
		`"nuclei_template":"http/cves/2021/CVE-2021-41773.yaml"}}`
	if err := os.WriteFile(corpus, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", corpus)

	findings := []types.Finding{{
		ID: "f1", RuleID: "httpx::probe", Tool: "httpx", Severity: types.SeverityInfo,
		Endpoint: "https://api.example.com",
		ToolArgs: map[string]string{"webserver": "Apache httpd/2.4.49", "status": "200"},
	}}

	got := NewHandler().PlanEscalation(
		types.Asset{Type: types.AssetAPI, Target: "https://api.example.com"},
		[]string{"GET https://api.example.com/users"}, // a non-empty surface, so kiterunner stays out
		findings,
	)

	var probed bool
	for _, d := range got {
		if strings.Contains(strings.ToLower(d.EscalatedFrom), "threat") {
			probed = true
			if d.Tool == nil || d.Tool.Name() != "nuclei" {
				t.Errorf("the probe should dispatch nuclei, got %+v", d.Tool)
			}
		}
	}
	if !probed {
		t.Fatalf("an API served by software with a KEV-listed CVE produced no threat-informed probe: %+v", got)
	}
}
