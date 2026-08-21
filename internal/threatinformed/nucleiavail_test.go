package threatinformed

import (
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// The corpus file is unmarshalled straight into Entry, and Go's field matching is
// case-insensitive but not underscore-insensitive. Without the json tag `nuclei_template`
// never reaches NucleiTemplate, every entry stays empty, and the planner silently reverts
// to assuming every CVE is testable — the exact bug the field exists to fix, restored
// invisibly. This is the shape the corpus writer actually emits.
func TestEntryDecodesTheCorpusFile(t *testing.T) {
	const corpusJSON = `{"CVE-2021-44228":{
	  "kev":{"listed":true},
	  "epss":{"score":0.97},
	  "exploits":["exploitdb:EDB-50592","metasploit:exploit/multi/http/log4shell_header_injection"],
	  "nuclei_template":"http/cves/2021/CVE-2021-44228.yaml"}}`
	var c Corpus
	if err := json.Unmarshal([]byte(corpusJSON), &c); err != nil {
		t.Fatal(err)
	}
	e := c["CVE-2021-44228"]
	if e.NucleiTemplate != "http/cves/2021/CVE-2021-44228.yaml" {
		t.Errorf("NucleiTemplate = %q — the corpus key did not reach the field", e.NucleiTemplate)
	}
	if e.KEV == nil || !e.KEV.Listed || e.EPSS == nil || len(e.Exploits) != 2 {
		t.Errorf("the other fields regressed: %+v", e)
	}
}

func obs() []Observation {
	return []Observation{{Product: "Apache httpd", Version: "2.4.49", URL: "http://t.test"}}
}

// A CVE nuclei has no template for must not consume a capped probe slot: `-id CVE-…` for
// a template that does not exist matches nothing, and every wasted slot displaces one that
// would have run.
func TestPlan_UntestableCVEDoesNotConsumeASlot(t *testing.T) {
	c := Corpus{
		"CVE-2021-41773": {KEV: &types.KEVStatus{Listed: true, Product: "Apache HTTP Server"},
			NucleiTemplate: "http/cves/2021/CVE-2021-41773.yaml"},
		"CVE-2021-42013": {KEV: &types.KEVStatus{Listed: true, Product: "Apache HTTP Server"}},
	}
	probes, untestable := PlanWithGaps(c, obs(), Options{MaxProbes: 10})
	if len(probes) != 1 || probes[0].CVE != "CVE-2021-41773" {
		t.Errorf("probes = %+v; want only the CVE with a template", probes)
	}
	if len(untestable) != 1 || untestable[0].CVE != "CVE-2021-42013" {
		t.Errorf("untestable = %+v; want the templateless CVE reported, not dropped", untestable)
	}
}

// The untestable set is the honest half. A KEV CVE matching an observed product that just
// VANISHES is how a clean probe report comes to mean "we checked everything" when it means
// "we checked what we could".
func TestPlan_UntestableIsReportedNotSilent(t *testing.T) {
	c := Corpus{"CVE-2021-42013": {KEV: &types.KEVStatus{Listed: true, Product: "Apache HTTP Server"},
		NucleiTemplate: ""}}
	// A second entry carries a template, so the corpus DOES know about availability.
	c["CVE-2000-0001"] = Entry{EPSS: &types.EPSSScore{Score: 0.9}, NucleiTemplate: "x.yaml"}

	probes, untestable := PlanWithGaps(c, obs(), Options{MaxProbes: 10})
	if len(probes) != 0 {
		t.Errorf("probes = %+v; the Apache CVE has no template and the other matches no product", probes)
	}
	if len(untestable) != 1 || untestable[0].CVE != "CVE-2021-42013" {
		t.Fatalf("untestable = %+v; the matched-but-untestable CVE must be named", untestable)
	}
	if !untestable[0].Reason.KEV || !untestable[0].Reason.ProductMatch {
		t.Error("the untestable probe must keep its evidence — that is what makes it worth reporting")
	}
}

// A corpus with NO template data (an older one, or a refresh that could not reach the
// index) must degrade to the previous behaviour rather than silencing the plan entirely.
// Reading "we know nothing about availability" as "nothing is available" would turn a
// missing feed into zero probes.
func TestPlan_CorpusWithoutTemplateDataStillPlans(t *testing.T) {
	c := Corpus{"CVE-2021-41773": {KEV: &types.KEVStatus{Listed: true, Product: "Apache HTTP Server"}}}
	probes, untestable := PlanWithGaps(c, obs(), Options{MaxProbes: 10})
	if len(probes) != 1 {
		t.Errorf("probes = %+v; a corpus with no availability data must still plan", probes)
	}
	if len(untestable) != 0 {
		t.Errorf("untestable = %+v; nothing is KNOWN untestable when the corpus carries no index", untestable)
	}
	if !probes[0].Testable {
		t.Error("with no index, a probe is assumed testable — the old behaviour, stated")
	}
}

// Plan keeps its signature so dispatch-only callers are unchanged.
func TestPlan_SignatureUnchanged(t *testing.T) {
	c := Corpus{"CVE-2021-41773": {KEV: &types.KEVStatus{Listed: true, Product: "Apache HTTP Server"},
		NucleiTemplate: "x.yaml"}}
	if got := Plan(c, obs(), Options{MaxProbes: 10}); len(got) != 1 {
		t.Errorf("Plan = %+v, want 1", got)
	}
}
