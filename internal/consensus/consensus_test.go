package consensus

import (
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

type staticJuror struct {
	v   Verdict
	err error
}

func (s staticJuror) Judge(context.Context, types.Finding) (Verdict, error) { return s.v, s.err }

func fp(r string) Juror {
	return staticJuror{v: Verdict{FalsePositive: true, Confidence: 0.9, Rationale: r}}
}
func tp(r string) Juror {
	return staticJuror{v: Verdict{FalsePositive: false, Confidence: 0.9, Rationale: r}}
}
func errJ() Juror { return staticJuror{err: errors.New("juror down")} }

func TestValidate_Majority(t *testing.T) {
	f := types.Finding{ID: "x", RuleID: "sast::sqli", Severity: types.SeverityHigh}

	// 2 FP, 1 TP → majority false positive.
	d := Validate(context.Background(), f, []Juror{fp("a"), fp("b"), tp("c")})
	if !d.FalsePositive || d.Votes != 3 || d.FPVotes != 2 {
		t.Errorf("2/3 FP should be FalsePositive, got %+v", d)
	}
	if d.Unanimous {
		t.Error("2-1 is not unanimous")
	}
	if d.Agreement < 0.66 || d.Agreement > 0.67 {
		t.Errorf("agreement = %.2f, want ~0.67", d.Agreement)
	}
	if len(d.Rationales) != 3 {
		t.Errorf("want 3 rationales (the audit trail), got %d", len(d.Rationales))
	}

	// 2 TP, 1 FP → not a false positive (keep the finding).
	if d := Validate(context.Background(), f, []Juror{tp("a"), tp("b"), fp("c")}); d.FalsePositive {
		t.Errorf("2/3 TP must NOT be FalsePositive, got %+v", d)
	}

	// Unanimous FP.
	if d := Validate(context.Background(), f, []Juror{fp("a"), fp("b"), fp("c")}); !d.FalsePositive || !d.Unanimous || d.Agreement != 1 {
		t.Errorf("unanimous FP expected, got %+v", d)
	}
}

func TestValidate_FailOpen(t *testing.T) {
	f := types.Finding{ID: "x"}

	// One juror errors → 2 valid votes; majority still decides.
	if d := Validate(context.Background(), f, []Juror{fp("a"), fp("b"), errJ()}); !d.FalsePositive || d.Votes != 2 {
		t.Errorf("a failed juror should be skipped, majority of the rest decides; got %+v", d)
	}

	// A tie (2 valid, 1 each) → fail open: NOT a false positive (never drop a real finding).
	if d := Validate(context.Background(), f, []Juror{fp("a"), tp("b"), errJ()}); d.FalsePositive {
		t.Errorf("a tie must fail open (not FP), got %+v", d)
	}

	// All jurors error → no votes → fail open.
	if d := Validate(context.Background(), f, []Juror{errJ(), errJ(), errJ()}); d.FalsePositive || d.Votes != 0 {
		t.Errorf("an all-failed panel must fail open with 0 votes, got %+v", d)
	}
}

func TestParseVerdict_Tolerant(t *testing.T) {
	// JSON wrapped in prose + a code fence — models do this.
	v, err := parseVerdict("Sure!\n```json\n{\"false_positive\": true, \"confidence\": 1.4, \"rationale\": \"generic tech fingerprint\"}\n```\n")
	if err != nil {
		t.Fatalf("should parse wrapped JSON: %v", err)
	}
	if !v.FalsePositive || v.Confidence != 1 { // confidence clamped to 1
		t.Errorf("parsed = %+v, want FP + clamped confidence 1", v)
	}
	if _, err := parseVerdict("not json at all"); err == nil {
		t.Error("garbage must error (→ the juror is skipped, never a silent vote)")
	}
}

func TestLLMJuror_AndDefaultPanel(t *testing.T) {
	f := types.Finding{ID: "x", RuleID: "sast::xss", Severity: types.SeverityMedium, Title: "Reflected XSS"}

	// A fake LLM: the skeptic + exploitation personas call it FP; the context one calls it TP.
	complete := func(_ context.Context, prompt string) (string, error) {
		if containsAny(prompt, "skeptical", "exploitation-focused") {
			return `{"false_positive": true, "confidence": 0.8, "rationale": "no reachable sink"}`, nil
		}
		return `{"false_positive": false, "confidence": 0.7, "rationale": "applies in this template"}`, nil
	}
	d := Validate(context.Background(), f, DefaultJurors(complete))
	if d.Votes != 3 || !d.FalsePositive || d.FPVotes != 2 {
		t.Errorf("default 3-juror panel with 2 FP votes should decide FP, got %+v", d)
	}

	// nil Complete → the juror errors (skipped), not a panic.
	if _, err := (LLMJuror{}).Judge(context.Background(), f); err == nil {
		t.Error("nil Complete should error")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
