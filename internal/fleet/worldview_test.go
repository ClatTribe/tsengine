package fleet

import (
	"errors"
	"fmt"
	"testing"
)

func TestUpdate_RefusesEvidencelessClaim(t *testing.T) {
	w := New()
	err := w.Update([]Claim{{Route: "web:https://x/a", Class: "sqli", Verdict: Vulnerable, Evidence: nil}})
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("a claim with no evidence must be refused with ErrNoEvidence, got %v", err)
	}
	// The batch must not half-apply: nothing entered.
	if len(w.Verdicts()) != 0 {
		t.Errorf("a refused batch must mutate nothing, got %d entries", len(w.Verdicts()))
	}
	// Empty-string evidence is also no evidence.
	if err := w.Update([]Claim{{Route: "r", Class: "c", Verdict: Clean, Evidence: []string{""}}}); !errors.Is(err, ErrNoEvidence) {
		t.Errorf("empty-string evidence must be refused, got %v", err)
	}
}

func TestUpdate_AllOrNothing(t *testing.T) {
	w := New()
	// second claim is invalid → the whole batch is rejected, first claim must NOT land.
	err := w.Update([]Claim{
		{Route: "r", Class: "sqli", Verdict: Vulnerable, Evidence: []string{"t-1"}},
		{Route: "r", Class: "xss", Verdict: Vulnerable, Evidence: nil},
	})
	if err == nil {
		t.Fatal("batch with an invalid claim must error")
	}
	if len(w.Verdicts()) != 0 {
		t.Errorf("no claim from a rejected batch may land, got %d", len(w.Verdicts()))
	}
}

func TestMerge_VulnerableAndCleanIsContested(t *testing.T) {
	w := New()
	must(t, w.Update([]Claim{{Route: "r", Class: "authz", Verdict: Clean, Evidence: []string{"t-1"}}}))
	must(t, w.Update([]Claim{{Route: "r", Class: "authz", Verdict: Vulnerable, Evidence: []string{"t-2"}}}))
	v, ok := w.Get("r", "authz")
	if !ok || v.Verdict != Contested {
		t.Fatalf("Clean then Vulnerable on the same route×class must be Contested, got %q", v.Verdict)
	}
	// Evidence from BOTH sides is retained (auditable disagreement), sorted.
	if len(v.Evidence) != 2 || v.Evidence[0] != "t-1" || v.Evidence[1] != "t-2" {
		t.Errorf("Contested must keep both sides' evidence, got %v", v.Evidence)
	}
	// A third claim never resolves Contested deterministically (only adjudication does).
	must(t, w.Update([]Claim{{Route: "r", Class: "authz", Verdict: Vulnerable, Evidence: []string{"t-3"}}}))
	if v, _ := w.Get("r", "authz"); v.Verdict != Contested {
		t.Errorf("Contested is terminal under merge, got %q", v.Verdict)
	}
}

func TestMerge_PrecedenceNonConflicting(t *testing.T) {
	cases := []struct {
		a, b, want Verdict
	}{
		{Denied, Clean, Clean},           // tested-safe beats could-not-test
		{Inconclusive, Denied, Denied},   // could-not-test beats ambiguous
		{Vulnerable, Denied, Vulnerable}, // proven beats could-not-test (NOT contested — Denied isn't a Clean)
		{Vulnerable, Inconclusive, Vulnerable},
		{Clean, Clean, Clean},
		{Denied, Inconclusive, Denied},
	}
	for _, c := range cases {
		w := New()
		must(t, w.Update([]Claim{{Route: "r", Class: "x", Verdict: c.a, Evidence: []string{"t-a"}}}))
		must(t, w.Update([]Claim{{Route: "r", Class: "x", Verdict: c.b, Evidence: []string{"t-b"}}}))
		if v, _ := w.Get("r", "x"); v.Verdict != c.want {
			t.Errorf("resolve(%s,%s)=%s, want %s", c.a, c.b, v.Verdict, c.want)
		}
	}
}

// resolve must be commutative and associative (the golden-merge guarantee): the worldview is a pure
// function of the SET of claims, not the order they arrived.
func TestResolve_CommutativeAndAssociative(t *testing.T) {
	all := []Verdict{Vulnerable, Clean, Denied, Inconclusive, Contested}
	for _, a := range all {
		for _, b := range all {
			if resolve(a, b) != resolve(b, a) {
				t.Errorf("not commutative: resolve(%s,%s)=%s but resolve(%s,%s)=%s", a, b, resolve(a, b), b, a, resolve(b, a))
			}
			for _, c := range all {
				l := resolve(resolve(a, b), c)
				r := resolve(a, resolve(b, c))
				if l != r {
					t.Errorf("not associative on {%s,%s,%s}: %s vs %s", a, b, c, l, r)
				}
			}
		}
	}
}

// TestMerge_OrderIndependent is the golden property: the same claim set applied in different orders
// (and different batch groupings) yields an identical worldview.
func TestMerge_OrderIndependent(t *testing.T) {
	claims := []Claim{
		{Route: "web:https://x/a", Class: "sqli", Verdict: Vulnerable, Evidence: []string{"t-1"}},
		{Route: "web:https://x/a", Class: "sqli", Verdict: Clean, Evidence: []string{"t-2"}}, // → Contested
		{Route: "web:https://x/a", Class: "xss", Verdict: Clean, Evidence: []string{"t-3"}},
		{Route: "web:https://x/b", Class: "authz", Verdict: Denied, Evidence: []string{"t-4"}},
		{Route: "web:https://x/b", Class: "authz", Verdict: Clean, Evidence: []string{"t-5"}}, // → Clean (precedence)
	}
	golden := snapshot(buildOne(t, claims))

	// Reverse order, one-claim-per-batch, and shuffled-by-index groupings must all match.
	rev := append([]Claim(nil), claims...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if got := snapshot(buildOne(t, rev)); got != golden {
		t.Errorf("reverse order changed the worldview:\n got=%s\nwant=%s", got, golden)
	}
	// Split into odd/even batches.
	w := New()
	var evenB, oddB []Claim
	for i, c := range claims {
		if i%2 == 0 {
			evenB = append(evenB, c)
		} else {
			oddB = append(oddB, c)
		}
	}
	must(t, w.Update(oddB))
	must(t, w.Update(evenB))
	if got := snapshot(w); got != golden {
		t.Errorf("batch regrouping changed the worldview:\n got=%s\nwant=%s", got, golden)
	}
}

func TestCounts(t *testing.T) {
	w := New()
	must(t, w.Update([]Claim{
		{Route: "r1", Class: "sqli", Verdict: Vulnerable, Evidence: []string{"t-1"}},
		{Route: "r2", Class: "xss", Verdict: Clean, Evidence: []string{"t-2"}},
		{Route: "r3", Class: "authz", Verdict: Denied, Evidence: []string{"t-3"}},
	}))
	c := w.Counts()
	if c[Vulnerable] != 1 || c[Clean] != 1 || c[Denied] != 1 {
		t.Errorf("counts wrong: %v", c)
	}
}

// helpers

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func buildOne(t *testing.T, claims []Claim) *Worldview {
	t.Helper()
	w := New()
	for _, c := range claims {
		must(t, w.Update([]Claim{c}))
	}
	return w
}

func snapshot(w *Worldview) string {
	s := ""
	for _, v := range w.Verdicts() {
		s += fmt.Sprintf("%s|%s=%s ev=%v w=%d\n", v.Route, v.Class, v.Verdict, v.Evidence, v.Workers)
	}
	return s
}
