package adapters

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestThreatIntel_LookupKnownCVE(t *testing.T) {
	a := NewThreatIntel()
	// CVE-2021-44228 (Log4Shell) is in the pinned corpus.
	summary, ok := a.LookupCVE(context.Background(), "CVE-2021-44228")
	if !ok {
		t.Fatal("Log4Shell should be in the pinned corpus")
	}
	for _, want := range []string{"CVE-2021-44228", "CVSS", "KEV", "EPSS"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q in:\n%s", want, summary)
		}
	}
}

func TestThreatIntel_CaseAndWhitespaceInsensitive(t *testing.T) {
	a := NewThreatIntel()
	if _, ok := a.LookupCVE(context.Background(), "  cve-2021-44228 "); !ok {
		t.Error("lookup should normalize case + whitespace")
	}
}

func TestThreatIntel_UnknownCVE(t *testing.T) {
	a := NewThreatIntel()
	if _, ok := a.LookupCVE(context.Background(), "CVE-1999-0001"); ok {
		t.Error("a CVE absent from the corpus must report not-found (no live-API fallback)")
	}
}

func TestRenderThreatIntel_KEVAndEPSS(t *testing.T) {
	ti := &types.ThreatIntel{
		CVSS:     10.0,
		KEV:      &types.KEVStatus{Listed: true, DateAdded: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)},
		EPSS:     &types.EPSSScore{Score: 0.975, Percentile: 0.999},
		Exploits: []string{"Metasploit", "ExploitDB"},
	}
	out := renderThreatIntel("CVE-2021-44228", ti)
	for _, want := range []string{"CVSS 10.0", "KEV: LISTED", "2021-12-10", "EPSS 0.9750", "Metasploit"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in: %s", want, out)
		}
	}
}
