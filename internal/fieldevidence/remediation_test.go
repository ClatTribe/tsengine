package fieldevidence

import (
	"strconv"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func remAct(id, class, rtype, status string) platform.Action {
	a := platform.Action{ID: id, Status: platform.ActApplied,
		FindingKeys: []string{class + "|https://x/" + id},
		Payload:     map[string]any{"remediation_type": rtype}}
	if status != "" {
		a.Verification = &platform.FixVerification{Status: status}
	}
	return a
}

func remHistory(class, rtype, status string, n int) []platform.Action {
	var out []platform.Action
	for i := 0; i < n; i++ {
		out = append(out, remAct(status+strconv.Itoa(i), class, rtype, status))
	}
	return out
}

// THE property: a remediation's track record is measurable from data already stored.
func TestRemediations_MeasuresWhetherTheFixActuallyClosedIt(t *testing.T) {
	var acts []platform.Action
	acts = append(acts, remHistory("nuclei::sqli", "parameterize_query", platform.FixStatusFixed, 8)...)
	acts = append(acts, remHistory("nuclei::sqli", "parameterize_query", platform.FixStatusStillPresent, 2)...)
	c := RemediationsForTenant("t1", acts, Options{})

	e, ok := c.For("nuclei::sqli", "parameterize_query")
	if !ok {
		t.Fatal("10 decided applications must be enough to report")
	}
	if e.Closed != 8 || e.NotClosed != 2 {
		t.Fatalf("want 8 closed / 2 not, got %+v", e)
	}
	if got := e.ClosureRate(); got != 0.8 {
		t.Errorf("closure rate = %.2f, want 0.80", got)
	}
}

// THE HONESTY LINK between the two feeds: F1 withholds a confirmation when a clean re-scan for that
// class has been contradicted before. F2 must NOT then count that withheld confirmation as a fix
// that worked — that would launder the exact uncertainty F1 exists to record, and it would do it in
// the direction that flatters us.
func TestRemediations_AWithheldConfirmationIsNotASuccess(t *testing.T) {
	var acts []platform.Action
	acts = append(acts, remHistory("r1", "t", platform.FixStatusFixed, 5)...)
	acts = append(acts, remHistory("r1", "t", platform.FixStatusRescanUnconfirmed, 5)...)
	c := RemediationsForTenant("t1", acts, Options{})

	e, ok := c.For("r1", "t")
	if !ok {
		t.Fatal("5 decided applications must be enough")
	}
	if e.Closed != 5 || e.Unproven != 5 {
		t.Fatalf("want 5 closed / 5 unproven, got %+v", e)
	}
	// Excluded from the rate in BOTH directions: not a success, and not a failure either.
	if e.Decided() != 5 {
		t.Errorf("unproven must not enter the denominator, got %d decided", e.Decided())
	}
	if got := e.ClosureRate(); got != 1.0 {
		t.Errorf("rate must be over DECIDED applications only, got %.2f", got)
	}
}

// Absence must render as nothing at all. "0 of 0" beside a proposed fix reads as a fix that never
// works, which is the opposite of what an absence of data means.
func TestRemediations_ThinOrAbsentHistoryReportsNothing(t *testing.T) {
	cases := map[string]*RemediationCorpus{
		"nil corpus":  nil,
		"no history":  RemediationsForTenant("t1", nil, Options{}),
		"below floor": RemediationsForTenant("t1", remHistory("r1", "t", platform.FixStatusFixed, 2), Options{}),
		"never applied": RemediationsForTenant("t1", []platform.Action{
			{ID: "x", Status: platform.ActProposed, FindingKeys: []string{"r1|e"},
				Payload: map[string]any{"remediation_type": "t"}}}, Options{}),
		"no remediation_type": RemediationsForTenant("t1", []platform.Action{
			{ID: "x", Status: platform.ActApplied, FindingKeys: []string{"r1|e"},
				Verification: &platform.FixVerification{Status: platform.FixStatusFixed}}}, Options{}),
	}
	for name, c := range cases {
		if _, ok := c.For("r1", "t"); ok {
			t.Errorf("%s: must report nothing, not a zeroed record", name)
		}
	}
}

// A remediation type is attributed to the finding class it was applied against — a fix that works for
// one class says nothing about another.
func TestRemediations_KeyedOnClassAndTypeTogether(t *testing.T) {
	var acts []platform.Action
	acts = append(acts, remHistory("class-a", "upgrade", platform.FixStatusFixed, 6)...)
	acts = append(acts, remHistory("class-b", "upgrade", platform.FixStatusStillPresent, 6)...)
	c := RemediationsForTenant("t1", acts, Options{})

	a, aok := c.For("class-a", "upgrade")
	b, bok := c.For("class-b", "upgrade")
	if !aok || !bok {
		t.Fatal("both records must exist")
	}
	if a.ClosureRate() != 1 || b.ClosureRate() != 0 {
		t.Errorf("the same remediation type must be scored per class: a=%.2f b=%.2f",
			a.ClosureRate(), b.ClosureRate())
	}
	// The weakest list names the runbook that needs rewriting, worst first.
	w := c.Weakest()
	if len(w) != 1 || w[0].Class != "class-b" {
		t.Errorf("Weakest must name only the failing pairing, got %+v", w)
	}
}
