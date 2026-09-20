package rlvr

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// fakeProber replays a scripted response per probe URL, or an error for URLs meant to model
// an unreachable target. This is the record/replay Prober that lets the harness grade offline.
type fakeProber struct {
	byURL map[string]pentest.ProbeResult
	fail  map[string]bool // URLs that model a transport failure (unreachable target)
}

func (f fakeProber) Send(_ context.Context, p pentest.Probe) (pentest.ProbeResult, error) {
	if f.fail[p.URL] {
		return pentest.ProbeResult{}, errors.New("dial tcp: connection refused")
	}
	if r, ok := f.byURL[p.URL]; ok {
		return r, nil
	}
	return pentest.ProbeResult{Status: 404, Body: ""}, nil
}

// A reflect spec: the predicate holds iff the canary token appears in the body. The canary is
// embedded in the marker arg (contains predicate), mirroring the product's unforgeable-proof rule.
func reflectSpec(url, token string) pentest.DemoSpec {
	return pentest.DemoSpec{
		Class:     "xss",
		Probes:    []pentest.Probe{{Method: "GET", URL: url}},
		Predicate: pentest.PredContains,
		Args:      map[string]string{"marker": token},
		Proof:     "canary reflected",
	}
}

func TestGrade_ExploitedWhenPredicateHolds(t *testing.T) {
	tok := "tsX-canary-9f3a"
	url := "http://target/echo?q=" + tok
	pr := fakeProber{byURL: map[string]pentest.ProbeResult{
		url: {Status: 200, Body: "you said: " + tok}, // the app reflected the canary → real
	}}
	g := Grade(context.Background(), pr, nil, nil, Episode{
		Spec: reflectSpec(url, tok), Truth: TruthVulnerable,
	})
	if g.Verdict != Exploited {
		t.Fatalf("want Exploited, got %s", g.Verdict)
	}
	if g.Reward != 1 {
		t.Fatalf("Exploited must reward 1, got %v", g.Reward)
	}
}

func TestGrade_NotExploitedWhenCanaryAbsent(t *testing.T) {
	tok := "tsX-canary-9f3a"
	url := "http://target/echo?q=" + tok
	pr := fakeProber{byURL: map[string]pentest.ProbeResult{
		url: {Status: 200, Body: "static homepage, no reflection"}, // patched: canary not echoed
	}}
	g := Grade(context.Background(), pr, nil, nil, Episode{
		Spec: reflectSpec(url, tok), Truth: TruthPatched,
	})
	if g.Verdict != NotExploited {
		t.Fatalf("want NotExploited, got %s", g.Verdict)
	}
	if g.Reward != 0 {
		t.Fatalf("NotExploited must reward 0, got %v", g.Reward)
	}
}

// The load-bearing case: an unreachable target is Ungradeable, NEVER NotExploited. If this
// regresses, the corpus starts teaching the model that a timeout is a safe target.
func TestGrade_UnreachableTargetIsUngradeableNotNegative(t *testing.T) {
	tok := "tsX-canary-9f3a"
	url := "http://down/echo?q=" + tok
	pr := fakeProber{fail: map[string]bool{url: true}}
	g := Grade(context.Background(), pr, nil, nil, Episode{
		Spec: reflectSpec(url, tok), Truth: TruthVulnerable,
	})
	if g.Verdict != Ungradeable {
		t.Fatalf("unreachable target must be Ungradeable, got %s", g.Verdict)
	}
	// And it must not poison the confusion matrix as a false negative.
	c := Score([]Graded{g})
	if c.FN != 0 || c.TP != 0 {
		t.Fatalf("ungradeable leaked into the matrix: %+v", c)
	}
	if c.Ungradeable != 1 {
		t.Fatalf("want 1 dropped, got %d", c.Ungradeable)
	}
}

// An ill-formed spec (unknown predicate / missing arg) is the MODEL's failure → NotExploited,
// not Ungradeable. DemoFromSpec is the gate; a bad proposal is a real negative signal.
func TestGrade_IllFormedSpecIsModelSideNegative(t *testing.T) {
	g := Grade(context.Background(), fakeProber{}, nil, nil, Episode{
		Spec: pentest.DemoSpec{Predicate: pentest.PredContains, Probes: nil}, // no probes → nil demo
	})
	if g.Verdict != NotExploited {
		t.Fatalf("ill-formed spec must be NotExploited, got %s", g.Verdict)
	}
}

func TestSpecificity_IsHeadlineAndUndefinedWithoutNegatives(t *testing.T) {
	// A corpus of only vulnerable targets: specificity is undefined, because there were no
	// fakes to reject — a perfect score here would be vacuous.
	c := Confusion{TP: 10, FN: 0}
	if _, ok := c.Specificity(); ok {
		t.Fatal("specificity over zero patched targets must be undefined (vacuous-pass guard)")
	}
	// With patched targets, specificity is the fraction of fakes correctly rejected.
	c = Confusion{TP: 8, FN: 2, TN: 9, FP: 1}
	s, ok := c.Specificity()
	if !ok || s != 0.9 {
		t.Fatalf("want specificity 0.9, got %v ok=%v", s, ok)
	}
}

func TestJSONL_RoundTrip(t *testing.T) {
	gs := []Graded{
		{Episode: Episode{ID: "e1", Truth: TruthVulnerable}, Verdict: Exploited, Reward: 1},
		{Episode: Episode{ID: "e2", Truth: TruthPatched}, Verdict: NotExploited},
		{Episode: Episode{ID: "e3"}, Verdict: Ungradeable},
	}
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, gs); err != nil {
		t.Fatal(err)
	}
	back, err := ReadJSONL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 3 || back[0].Episode.ID != "e1" || back[2].Verdict != Ungradeable {
		t.Fatalf("round-trip lost data: %+v", back)
	}
}

// Guard against the finding type drifting out from under the episode (compile-time use).
var _ = types.Finding{}
