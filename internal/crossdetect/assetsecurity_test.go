package crossdetect

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestAssetSecurityPosture_FPAwareAndHonest(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-web", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "a-clean", Type: "web_application", Target: "https://marketing.acme.com"},
		{ID: "a-unscanned", Type: "api", Target: "https://api.acme.com"},
	}
	findings := []types.Finding{
		// a-web: a CONFIRMED (corroborated) high → drives "at risk"
		{ID: "f1", Severity: types.SeverityHigh, Endpoint: "https://app.acme.com/login",
			VerificationStatus: types.VerificationCorroborated},
		// a-web: an UNCONFIRMED pattern_match → counted separately, never inflates the confirmed risk
		{ID: "f2", Severity: types.SeverityMedium, Endpoint: "https://app.acme.com/search",
			VerificationStatus: types.VerificationPatternMatch},
		// endpoint ties to no asset → dropped (no fabricated attribution)
		{ID: "f3", Severity: types.SeverityCritical, Endpoint: "internal-only-host/x"},
	}
	scanned := map[string]bool{"a-web": true, "a-clean": true} // a-unscanned never scanned

	got := AssetSecurityPosture(assets, findings, scanned)
	by := map[string]AssetSecurity{}
	for _, p := range got {
		by[p.AssetID] = p
	}

	web := by["a-web"]
	if web.Findings != 2 || web.Confirmed != 1 || web.Unconfirmed != 1 || web.High != 1 {
		t.Fatalf("a-web counts wrong: %+v", web)
	}
	if !strings.Contains(web.Verdict, "At risk") || !strings.Contains(web.Verdict, "confirmed") {
		t.Errorf("a-web with a confirmed high should read 'At risk … confirmed', got %q", web.Verdict)
	}

	// scanned-clean asset: honest "no issues found", NEVER a bare "secure"
	clean := by["a-clean"]
	if clean.Attributed || !clean.Scanned {
		t.Fatalf("a-clean should be scanned + unattributed, got %+v", clean)
	}
	if !strings.Contains(clean.Verdict, "No issues found") || strings.Contains(clean.Verdict, "is secure") {
		t.Errorf("a-clean must say 'no issues found … not a guarantee', never claim secure: %q", clean.Verdict)
	}

	// never-scanned asset is explicit about it (no false all-clear)
	un := by["a-unscanned"]
	if un.Verdict != "Not yet scanned" {
		t.Errorf("a-unscanned verdict should be 'Not yet scanned', got %q", un.Verdict)
	}

	// ordering: the at-risk asset leads
	if got[0].AssetID != "a-web" {
		t.Errorf("the at-risk asset should sort first, got %q", got[0].AssetID)
	}
}
