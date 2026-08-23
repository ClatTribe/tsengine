package retest

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// stubPolicy distrusts exactly the listed classes and knows nothing about anything else.
type stubPolicy struct {
	distrusted map[string]bool
	knownOnly  map[string]bool // classes it has an opinion about at all
}

func (s stubPolicy) RescanSufficient(class string) (bool, bool) {
	if s.knownOnly != nil && !s.knownOnly[class] {
		return true, false
	}
	if s.distrusted[class] {
		return false, true
	}
	return true, true
}

// THE property: for a class whose clean re-scans have been contradicted before, the re-scan alone no
// longer makes the terminal claim.
func TestVerifyWithPolicy_DistrustedClassIsNotConfirmedByRescanAlone(t *testing.T) {
	acts := []platform.Action{applied("a1", "nuclei::sqli|https://a")}
	got := VerifyWithPolicy(acts, nil, t0, detect.AllProducers(),
		stubPolicy{distrusted: map[string]bool{"nuclei::sqli": true}})
	if len(got) != 1 {
		t.Fatalf("want one changed action, got %d", len(got))
	}
	v := got[0].Verification
	if v.Status != platform.FixStatusRescanUnconfirmed {
		t.Fatalf("want %s, got %s", platform.FixStatusRescanUnconfirmed, v.Status)
	}
	if !strings.Contains(v.Evidence, "contradicted by a live exploit") {
		t.Errorf("the evidence must say WHY it was withheld, got: %s", v.Evidence)
	}
	// It must not claim the fix failed either — "gone, on evidence we know has failed" is a third thing.
	if strings.Contains(v.Evidence, "still present") {
		t.Errorf("a withheld confirmation must not read as a failed fix, got: %s", v.Evidence)
	}
}

// It can only ever DEMAND MORE evidence. Every one of these must behave exactly as it does today.
func TestVerifyWithPolicy_OnlyEverTightens(t *testing.T) {
	present := []types.Finding{find("nuclei::sqli", "https://a")}
	cases := []struct {
		name   string
		policy RescanPolicy
		cur    []types.Finding
		want   string
	}{
		{"nil policy is today's behaviour", nil, nil, platform.FixStatusFixed},
		{"unknown class is unchanged", stubPolicy{knownOnly: map[string]bool{}}, nil, platform.FixStatusFixed},
		{"clean record is unchanged", stubPolicy{distrusted: map[string]bool{}}, nil, platform.FixStatusFixed},
		// The one that matters most: a distrusted class must NEVER turn a still-present into a fix.
		{"distrusted cannot rescue a still-present", stubPolicy{distrusted: map[string]bool{"nuclei::sqli": true}},
			present, platform.FixStatusStillPresent},
	}
	for _, tc := range cases {
		got := VerifyWithPolicy([]platform.Action{applied("a1", "nuclei::sqli|https://a")}, tc.cur, t0,
			detect.AllProducers(), tc.policy)
		if len(got) != 1 || got[0].Verification.Status != tc.want {
			s := "none"
			if len(got) == 1 {
				s = got[0].Verification.Status
			}
			t.Errorf("%s: want %s, got %s", tc.name, tc.want, s)
		}
	}
}

// An action claims to resolve a SET. Confirming it terminally while one member rests on evidence we
// know has failed would close the whole remediation on that evidence — the same reasoning coversAll
// already applies to producers this pass could not observe.
func TestVerifyWithPolicy_OneDistrustedClassTaintsTheWholeAction(t *testing.T) {
	got := VerifyWithPolicy(
		[]platform.Action{applied("a1", "nuclei::headers|https://a", "nuclei::sqli|https://b")},
		nil, t0, detect.AllProducers(),
		stubPolicy{distrusted: map[string]bool{"nuclei::sqli": true}})
	if len(got) != 1 || got[0].Verification.Status != platform.FixStatusRescanUnconfirmed {
		t.Fatalf("one distrusted class must withhold the whole action's confirmation, got %+v", got)
	}
}

// A withheld confirmation must not be terminal, or demanding more evidence would freeze the action
// forever with no way to ever settle it.
func TestVerifyWithPolicy_WithheldConfirmationIsNotTerminal(t *testing.T) {
	a := applied("a1", "nuclei::sqli|https://a")
	a.Verification = &platform.FixVerification{Status: platform.FixStatusRescanUnconfirmed}
	// Same pass, now trusted (the corpus moved): it must be re-evaluated, not skipped as terminal.
	got := VerifyWithPolicy([]platform.Action{a}, nil, t0, detect.AllProducers(), nil)
	if len(got) != 1 || got[0].Verification.Status != platform.FixStatusFixed {
		t.Fatalf("a withheld confirmation must stay re-evaluable, got %+v", got)
	}
}

// THE TRAP: closed_with_proof requires that the re-scan agreed the finding was gone. Withholding the
// confirmation must not also make the product's STRONGEST claim unreachable — otherwise demanding
// more evidence destroys the reward for supplying it.
func TestApplyReattack_ClosedWithProofStillReachableFromAWithheldConfirmation(t *testing.T) {
	a := applied("a1", "nuclei::sqli|https://a")
	a.Verification = &platform.FixVerification{Status: platform.FixStatusRescanUnconfirmed}
	got := ApplyReattack([]platform.Action{a},
		map[string]ReattackVerdict{"nuclei::sqli|https://a": {Verified: true, Exploitable: false,
			Evidence: "exploit re-run, no longer succeeds"}}, t0)
	if len(got) != 1 {
		t.Fatalf("want one changed action, got %d", len(got))
	}
	v := got[0].Verification
	if v.Status != StatusClosedWithProof {
		t.Fatalf("want %s, got %s", StatusClosedWithProof, v.Status)
	}
	// Status alone is NOT the property. Both the agreement branch and the disagreement branch end at
	// closed_with_proof; what separates them is whether the re-scan is recorded as having agreed. If
	// a withheld confirmation is not recognised as "the re-scan said gone", this action falls to the
	// disagreement branch and two things break at once: the customer is told the scanner "may be
	// seeing a variant — treat this as partial", a disagreement that never happened; and
	// RescanSaidFixed stays false, so fieldevidence.FromActions drops the row and the corpus is
	// silently starved of the labelled example it exists to collect.
	if v.Disagreement != "" {
		t.Errorf("both kinds of evidence agreed — no disagreement may be manufactured, got %q", v.Disagreement)
	}
	if !v.RescanSaidFixed {
		t.Error("the re-scan DID say gone; recording otherwise drops this labelled example from the corpus")
	}
	if strings.Contains(v.Evidence, "variant") {
		t.Errorf("an agreement must not be reported as a partial/variant result, got: %s", v.Evidence)
	}
}

// And the other direction still works: a live exploit beats the scanner's silence.
func TestApplyReattack_LiveExploitStillBeatsAWithheldConfirmation(t *testing.T) {
	a := applied("a1", "nuclei::sqli|https://a")
	a.Verification = &platform.FixVerification{Status: platform.FixStatusRescanUnconfirmed}
	got := ApplyReattack([]platform.Action{a},
		map[string]ReattackVerdict{"nuclei::sqli|https://a": {Verified: true, Exploitable: true}}, t0)
	if len(got) != 1 || got[0].Verification.Status != StatusStillExploitable {
		t.Fatalf("want %s, got %+v", StatusStillExploitable, got)
	}
}
