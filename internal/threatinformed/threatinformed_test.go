package threatinformed

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func kev(product, vendor string) *types.KEVStatus {
	return &types.KEVStatus{Listed: true, Product: product, Vendor: vendor}
}
func epss(s float64) *types.EPSSScore { return &types.EPSSScore{Score: s} }

// The headline behaviour: a KEV CVE whose catalogued product matches a
// recon-observed product is planned as a targeted probe. This is the loop that
// did not exist — intel deciding what to look for.
func TestPlan_KEVProductMatchIsTargeted(t *testing.T) {
	c := Corpus{
		"CVE-2021-41773": {KEV: kev("HTTP Server", "Apache"), EPSS: epss(0.9)},
		"CVE-2000-0001":  {EPSS: epss(0.5)}, // no product info → not matched
	}
	got := Plan(c, []Observation{{Product: "Apache httpd", Version: "2.4.49", URL: "http://h/"}}, Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 targeted probe, got %d: %+v", len(got), got)
	}
	p := got[0]
	if p.CVE != "CVE-2021-41773" {
		t.Errorf("probe CVE = %q", p.CVE)
	}
	if !p.Reason.ProductMatch || !p.Reason.KEV {
		t.Errorf("reason should record KEV + product match: %+v", p.Reason)
	}
	if p.URL != "http://h/" {
		t.Errorf("probe should carry the observed endpoint, got %q", p.URL)
	}
	if p.TemplateID != "CVE-2021-41773" {
		t.Errorf("template id should be the CVE id (nuclei convention), got %q", p.TemplateID)
	}
}

// §10: a CVE with NO exploitation signal is never probed, even when its
// product matches. Absence of evidence is not a reason to spend budget.
func TestPlan_NoExploitationSignalIsNeverProbed(t *testing.T) {
	c := Corpus{"CVE-2019-9999": {KEV: &types.KEVStatus{Listed: false, Product: "HTTP Server", Vendor: "Apache"}}}
	if got := Plan(c, []Observation{{Product: "Apache httpd"}}, Options{}); len(got) != 0 {
		t.Fatalf("no KEV/EPSS/exploit signal must yield no probes, got %+v", got)
	}
}

// §10: nothing is planned from an empty corpus — no invented CVEs.
func TestPlan_EmptyCorpusYieldsNothing(t *testing.T) {
	if got := Plan(Corpus{}, []Observation{{Product: "nginx"}}, Options{}); got != nil {
		t.Fatalf("empty corpus must plan nothing, got %+v", got)
	}
}

// Default behaviour is evidence-TARGETED: an unmatched product does not
// produce speculative probes unless the operator opts into IntelOnly breadth.
func TestPlan_IntelOnlyIsOptInAndSubCapped(t *testing.T) {
	c := Corpus{}
	for _, id := range []string{"CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E"} {
		c[id] = Entry{KEV: kev("Something Else", "OtherVendor")}
	}
	obs := []Observation{{Product: "nginx"}}

	if got := Plan(c, obs, Options{}); len(got) != 0 {
		t.Fatalf("default plan must not include unmatched probes, got %d", len(got))
	}
	got := Plan(c, obs, Options{IntelOnly: true, MaxIntelOnly: 2})
	if len(got) != 2 {
		t.Fatalf("intel-only should be sub-capped to 2, got %d", len(got))
	}
	for _, p := range got {
		if p.Reason.ProductMatch {
			t.Errorf("intel-only probe should not claim a product match: %+v", p.Reason)
		}
	}
}

// Ranking: KEV (observed in-the-wild) outranks a high EPSS prediction, and a
// product match outranks the same evidence without one.
func TestPlan_RanksKEVAboveEPSS(t *testing.T) {
	c := Corpus{
		"CVE-KEV":  {KEV: kev("nginx", "F5"), EPSS: epss(0.2)},
		"CVE-EPSS": {KEV: kev("nginx", "F5"), EPSS: epss(0.99)},
	}
	// Both match + both KEV; the higher EPSS should lead on the tie-break of
	// equal KEV weight.
	got := Plan(c, []Observation{{Product: "nginx"}}, Options{})
	if len(got) != 2 {
		t.Fatalf("want 2 probes, got %d", len(got))
	}
	if got[0].CVE != "CVE-EPSS" {
		t.Errorf("higher EPSS should rank first among equal KEV, got %q then %q", got[0].CVE, got[1].CVE)
	}
	// A KEV-listed CVE must outrank a non-KEV one with the same EPSS.
	c2 := Corpus{
		"CVE-NOKEV":  {EPSS: epss(0.5), Exploits: []string{"edb:1"}},
		"CVE-YESKEV": {KEV: kev("nginx", "F5"), EPSS: epss(0.5)},
	}
	got2 := Plan(c2, []Observation{{Product: "nginx"}}, Options{IntelOnly: true})
	if got2[0].CVE != "CVE-YESKEV" {
		t.Errorf("KEV should outrank non-KEV at equal EPSS, got %q first", got2[0].CVE)
	}
}

// Bounding: a huge catalog can never blow up the scan.
func TestPlan_RespectsMaxProbes(t *testing.T) {
	c := Corpus{}
	for i := 0; i < 500; i++ {
		c["CVE-X-"+string(rune('a'+i%26))+itoa(i)] = Entry{KEV: kev("nginx", "F5"), EPSS: epss(0.9)}
	}
	got := Plan(c, []Observation{{Product: "nginx"}}, Options{MaxProbes: 7})
	if len(got) != 7 {
		t.Fatalf("MaxProbes=7 must bound the plan, got %d", len(got))
	}
}

// Determinism: the same inputs must produce the same ordered plan (map
// iteration order must not leak into the result).
func TestPlan_IsDeterministic(t *testing.T) {
	c := Corpus{}
	for i := 0; i < 40; i++ {
		c["CVE-"+itoa(i)] = Entry{KEV: kev("nginx", "F5"), EPSS: epss(float64(i%7) / 10)}
	}
	obs := []Observation{{Product: "nginx"}}
	first := Plan(c, obs, Options{})
	for n := 0; n < 5; n++ {
		again := Plan(c, obs, Options{})
		if len(again) != len(first) {
			t.Fatalf("plan length varies between runs: %d vs %d", len(again), len(first))
		}
		for i := range first {
			if again[i].CVE != first[i].CVE {
				t.Fatalf("plan order varies between runs at %d: %q vs %q", i, again[i].CVE, first[i].CVE)
			}
		}
	}
}

// Product matching must bridge scanner banners ("Apache httpd") and the CISA
// catalog's split vendor/product ("Apache" / "HTTP Server") — but only via
// real string containment, never a fuzzy guess.
func TestProductMatches(t *testing.T) {
	cases := []struct {
		observed, product, vendor string
		want                      bool
	}{
		{"apache httpd", "HTTP Server", "Apache", true}, // vendor side matches
		{"nginx", "nginx", "F5", true},
		{"openssh", "OpenSSH", "OpenBSD", true},
		{"nginx", "HTTP Server", "Apache", false}, // different tech
		{"", "HTTP Server", "Apache", false},      // nothing observed
		{"nginx", "", "", false},                  // no catalog product
	}
	for _, c := range cases {
		if got := productMatches(normalize(c.observed), c.product, c.vendor); got != c.want {
			t.Errorf("productMatches(%q, %q, %q) = %v, want %v", c.observed, c.product, c.vendor, got, c.want)
		}
	}
}

func TestNormalize_StripsBannerNoise(t *testing.T) {
	if got := normalize("Apache httpd"); got != "apache" {
		t.Errorf("normalize(Apache httpd) = %q, want apache", got)
	}
	if got := normalize("  NGINX  "); got != "nginx" {
		t.Errorf("normalize trims+lowercases, got %q", got)
	}
}

// No observation at all → no targeted probes (targeting needs a target).
func TestPlan_NoObservationsNoTargetedProbes(t *testing.T) {
	c := Corpus{"CVE-1": {KEV: kev("HTTP Server", "Apache")}}
	if got := Plan(c, nil, Options{}); len(got) != 0 {
		t.Fatalf("no observed tech → no targeted probes, got %+v", got)
	}
}

// Reason is the audit trail: it must carry the catalogued product so an
// operator can see WHY the probe ran.
func TestPlan_ReasonCarriesAuditTrail(t *testing.T) {
	c := Corpus{"CVE-Z": {KEV: kev("HTTP Server", "Apache"), Exploits: []string{"exploitdb:EDB-50383"}}}
	got := Plan(c, []Observation{{Product: "Apache httpd"}}, Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 probe, got %d", len(got))
	}
	r := got[0].Reason
	if !strings.EqualFold(r.KEVProduct, "HTTP Server") {
		t.Errorf("reason should name the catalogued product, got %q", r.KEVProduct)
	}
	if !r.PublicExploit {
		t.Error("reason should record the public-exploit reference")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
