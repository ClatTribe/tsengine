package cloudengine

import "testing"

// WithModel used to copy the whole client struct — which go vet rejects, because the usage counter
// holds atomics that must not be copied — and the copy started from a ZERO counter, so tokens spent
// through a tier-routed model vanished from the engagement total. The counter is now shared by
// pointer: one engagement, one total, whichever model a call was routed to.
func TestWithModel_SharesTheUsageCounter(t *testing.T) {
	a := &Anthropic{usage: &usageCounter{}, model: "base"}
	got, ok := a.WithModel("tier-2")
	if !ok {
		t.Fatal("WithModel with a model must succeed")
	}
	c := got.(*Anthropic)
	if c.model != "tier-2" || a.model != "base" {
		t.Fatalf("copy must be bound to the new model and leave the parent alone: copy=%q parent=%q", c.model, a.model)
	}
	c.usage.add(Usage{InputTokens: 10, OutputTokens: 5})
	if tot := a.TotalUsage(); tot.InputTokens != 10 || tot.OutputTokens != 5 {
		t.Fatalf("tokens spent through the model-bound copy must count toward the parent's total, got %+v", tot)
	}
	// A zero-value client (no constructor) must not panic on the nil counter.
	var z OpenAICompat
	z.usage.add(Usage{InputTokens: 1})
	if z.TotalUsage() != (Usage{}) {
		t.Fatalf("a nil counter reports zero usage, got %+v", z.TotalUsage())
	}
}
