package scubaingest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/scubaingest"
)

// CISA documents the semantic fields and not their casing, and publishes no example. A struct tag
// betting on one spelling silently matches nothing, so the resolver handles the documented
// alternatives explicitly — and this drives all of them rather than the one I happened to write first.
func TestParse_AcceptsEveryDocumentedSpelling(t *testing.T) {
	for _, doc := range []string{
		`{"Results":{"aad":[{"ControlID":"MS.AAD.1.1v1","Requirement":"Legacy auth SHALL be blocked","Result":"Fail","Criticality":"Shall"}]}}`,
		`{"results":{"aad":[{"controlId":"MS.AAD.1.1v1","requirement":"Legacy auth SHALL be blocked","result":"Fail","criticality":"Shall"}]}}`,
		`{"results":{"aad":[{"control_id":"MS.AAD.1.1v1","requirement_text":"Legacy auth SHALL be blocked","status":"Fail","severity":"Shall"}]}}`,
		`{"x":{"y":{"policy_id":"MS.AAD.1.1v1","Result":"Fail"}}}`,
	} {
		got, err := scubaingest.Parse([]byte(doc))
		if err != nil {
			t.Fatalf("spelling not handled: %v\n%s", err, doc)
		}
		if len(got) != 1 || got[0].PolicyID != "MS.AAD.1.1v1" || got[0].Result != "fail" {
			t.Errorf("wrong parse of %s: %+v", doc, got)
		}
	}
}

// THE guard that makes tolerant parsing safe. A document we cannot read must never render as a tenant
// with nothing wrong — that turns our inability to parse CISA's output into a clean bill of health.
func TestParse_UnrecognizedDocumentIsAnErrorNotACleanTenant(t *testing.T) {
	for _, doc := range []string{
		`{"results":{"aad":[{"someOtherField":"MS.AAD.1.1v1","verdict":"Fail"}]}}`, // id under an unknown key
		`{"metadata":{"tenant":"acme"}}`,                                           // right file, no results
		`[]`,
	} {
		_, err := scubaingest.Parse([]byte(doc))
		if !errors.Is(err, scubaingest.ErrNoPoliciesRecognized) {
			t.Errorf("want ErrNoPoliciesRecognized for %s, got %v", doc, err)
		}
	}
	if !strings.Contains(scubaingest.ErrNoPoliciesRecognized.Error(), "never become a pass") {
		t.Error("the error must say WHY it refuses to be silent")
	}
}

// Only an explicit Fail is a violation. Warning is advisory; Error and Omitted mean their tool could
// not judge it, and folding either into a failure attributes to CISA a verdict CISA declined to give.
func TestOutcome_OnlyAnExplicitFailIsAViolation(t *testing.T) {
	cases := map[string]struct{ failed, judged bool }{
		"Pass": {false, true}, "Fail": {true, true},
		"Warning": {false, false}, "Error": {false, false}, "Omitted": {false, false},
		"SomethingNew": {false, false}, // an unrecognized verdict is not a pass
	}
	for verdict, want := range cases {
		got, err := scubaingest.Parse([]byte(`{"a":{"ControlID":"MS.AAD.1.1v1","Result":"` + verdict + `"}}`))
		if err != nil {
			t.Fatalf("%s: %v", verdict, err)
		}
		if got[0].Failed() != want.failed || got[0].Judged() != want.judged {
			t.Errorf("%s: failed=%v judged=%v, want %+v", verdict, got[0].Failed(), got[0].Judged(), want)
		}
	}
}

// A policy id EMBEDDED IN PROSE is not a policy id, even when it sits in a field we do read.
//
// The first version of this test put the id under an unread key, so the field-alias lookup rejected
// it and the anchoring was never exercised — it passed for the wrong reason. The case anchoring
// actually guards is a recognised id field whose value is a sentence.
func TestParse_DoesNotLiftPolicyIDsOutOfText(t *testing.T) {
	for _, doc := range []string{
		`{"ControlID":"see MS.AAD.1.1v1 for details","Result":"Fail"}`,
		`{"ControlID":"MS.AAD.1.1v1 (deprecated)","Result":"Fail"}`,
		`{"note":"see MS.AAD.1.1v1 for details","Result":"Fail"}`, // and still not under an unread key
	} {
		if _, err := scubaingest.Parse([]byte(doc)); !errors.Is(err, scubaingest.ErrNoPoliciesRecognized) {
			t.Errorf("an id in prose must not become a result (%s), got %v", doc, err)
		}
	}
}

// THE point of correlating: finding where OUR detection was silent and CISA's was not.
func TestCorrelate_SeparatesOurGapFromTheirs(t *testing.T) {
	outcomes := []scubaingest.Outcome{
		{PolicyID: "MS.AAD.1.1v1", Result: "fail"},  // they failed it, we fired  -> agreed
		{PolicyID: "MS.AAD.2.1v1", Result: "fail"},  // they failed it, we silent -> WE missed
		{PolicyID: "MS.AAD.3.1v1", Result: "pass"},  // they passed it, we fired  -> THEY missed
		{PolicyID: "MS.AAD.4.1v1", Result: "pass"},  // both fine
		{PolicyID: "MS.AAD.5.1v1", Result: "error"}, // their run could not judge
		{PolicyID: "MS.AAD.6.1v1", Result: "fail"},  // we have no rule at all
	}
	rules := map[string][]string{
		"MS.AAD.1.1v1": {"r1"}, "MS.AAD.2.1v1": {"r2"},
		"MS.AAD.3.1v1": {"r3"}, "MS.AAD.4.1v1": {"r4"}, "MS.AAD.5.1v1": {"r5"},
	}
	fired := map[string]bool{"r1": true, "r3": true}

	c := scubaingest.Correlate(outcomes, fired, rules)
	if c.AgreedFail != 1 || c.WeMissed != 1 || c.TheyMissed != 1 || c.AgreedPass != 1 {
		t.Fatalf("want 1/1/1/1, got agreed=%d weMissed=%d theyMissed=%d agreedPass=%d",
			c.AgreedFail, c.WeMissed, c.TheyMissed, c.AgreedPass)
	}
	if c.Unjudged != 1 {
		t.Errorf("an errored run is unjudged, got %d", c.Unjudged)
	}
	// Unmapped is its OWN number: merged into WeMissed it reads as a detector that stayed quiet and
	// sends someone to debug a rule that does not exist.
	if c.Unmapped != 1 {
		t.Errorf("a policy with no rule mapping must be counted separately, got %d", c.Unmapped)
	}
}

// A partial ("~"-prefixed) mapping is a weaker adjacent check in the bench's vocabulary. It must not
// count as us having caught the policy, or a partial mapping would silently absorb a real gap.
func TestCorrelate_APartialMappingDoesNotCountAsCatchingIt(t *testing.T) {
	c := scubaingest.Correlate(
		[]scubaingest.Outcome{{PolicyID: "MS.AAD.1.1v1", Result: "fail"}},
		map[string]bool{"~adjacent": true},
		map[string][]string{"MS.AAD.1.1v1": {"~adjacent"}})
	if c.WeMissed != 1 {
		t.Fatalf("a partial mapping must not absorb the gap, got %+v", c)
	}
}

// "They missed" is not a win by default, and the caveat has to say so on the artifact itself.
func TestCorrelate_CaveatRefusesTheFlatteringReading(t *testing.T) {
	c := scubaingest.Correlate(nil, nil, nil)
	if !strings.Contains(c.Caveat, "candidate false positive") {
		t.Errorf("the caveat must name the other reading of they_missed, got: %s", c.Caveat)
	}
}
