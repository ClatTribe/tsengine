package threatinformed

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A CVE CISA says is being exploited RIGHT NOW could previously fail every clause of the signal
// gate — not KEV-catalogued, low EPSS, no public exploit in our feeds — and never be probed for.
//
// That is absence of evidence in OUR feeds read as evidence of absence, against a statement from
// the same authority that publishes KEV. KEV covers ~1,700 CVEs; CISA assesses far more.
func TestPlan_CISAActiveExploitationQualifiesWithoutKEV(t *testing.T) {
	corpus := map[string]Entry{
		"CVE-2099-0001": {
			// No KEV, no EPSS, no public exploit — only CISA's assessment.
			SSVC: &types.SSVC{Exploitation: "active", Automatable: "yes", TechnicalImpact: "total"},
		},
	}
	got := Plan(corpus, obs(), Options{MaxProbes: 10, IntelOnly: true, MaxIntelOnly: 10})
	if len(got) == 0 {
		t.Fatal("CISA says this is being exploited and we planned no probe for it — the gate read " +
			"the absence of a KEV entry as the absence of exploitation")
	}
	if !got[0].Reason.SSVCActive {
		t.Errorf("the probe must record WHY it was selected, got %+v", got[0].Reason)
	}
}

// The grounding rule still holds: an assessment that is not "active" is not an exploitation signal.
// "poc" would double-count the public-exploit feeds and "none" is the absence of one.
func TestPlan_APoCOrNoneAssessmentIsNotAnExploitationSignal(t *testing.T) {
	for _, ex := range []string{"none", "poc"} {
		corpus := map[string]Entry{"CVE-2099-0002": {SSVC: &types.SSVC{Exploitation: ex}}}
		if got := Plan(corpus, obs(), Options{MaxProbes: 10, IntelOnly: true, MaxIntelOnly: 10}); len(got) != 0 {
			t.Errorf("exploitation=%q is not a claim that it is being exploited, got %d probe(s)", ex, len(got))
		}
	}
}

// Automatable outranks a public exploit, and CISA-active outranks both while staying below KEV —
// a KEV entry additionally carries a federal remediation mandate and a stricter cataloguing bar,
// and ranking them equal would erase that.
func TestPriority_SSVCSignalsAreWeightedAgainstTheExistingOnes(t *testing.T) {
	kev := priority(Reason{KEV: true})
	active := priority(Reason{SSVCActive: true})
	auto := priority(Reason{SSVCAutomatable: true})
	pub := priority(Reason{PublicExploit: true})

	if !(kev > active) {
		t.Errorf("KEV (%v) must outrank CISA-active (%v): the catalogue carries a mandate the "+
			"assessment does not", kev, active)
	}
	if !(active > auto && auto > pub) {
		t.Errorf("want active(%v) > automatable(%v) > public-exploit(%v) — a weapon that must be "+
			"hand-driven reaches one target, an automatable one reaches an estate", active, auto, pub)
	}
}
