package cloudgraph

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// TestAddPrivescEdges_ConditionalEscalationMarkedConditional: when a principal's ONLY escalation
// permission is condition-gated (e.g. iam:CreateAccessKey requires MFA), the escalation is
// config-possible, NOT definite — a path through it must be flagged conditional so it's live-validated
// before being called real-impact (ADR-0002 / §10). AddPrivescEdges used cloudiam.CanDo, which discards
// the conditional bit, so the privesc edge was emitted with no Condition and Path.Conditional() read the
// path as DEFINITE — over-claiming certainty. (has_access edges already carry the conditional flag via
// HasAccess; privesc was the inconsistent one.)
func TestAddPrivescEdges_ConditionalEscalationMarkedConditional(t *testing.T) {
	s := New("acct", "aws")
	s.AddNode(&Node{ID: "p", Kind: KindPrincipal})
	condDoc, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey"],"Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`))
	s.AddPrivescEdges(map[string][]*cloudiam.Document{"p": {condDoc}})

	found := false
	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc && e.From == "p" {
			found = true
			if e.Condition == "" {
				t.Error("a condition-gated escalation must mark the privesc edge conditional — else the path is reported DEFINITE")
			}
		}
	}
	if !found {
		t.Fatal("expected a privesc edge for the (config-possible) conditional escalation")
	}

	// A firm (unconditional) escalation must NOT be marked conditional.
	s2 := New("acct", "aws")
	s2.AddNode(&Node{ID: "q", Kind: KindPrincipal})
	firmDoc, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey"],"Resource":"*"}]}`))
	s2.AddPrivescEdges(map[string][]*cloudiam.Document{"q": {firmDoc}})
	for _, e := range s2.Edges {
		if e.Kind == EdgePrivesc && e.From == "q" && e.Condition != "" {
			t.Errorf("a firm (unconditional) escalation must not be marked conditional, got %q", e.Condition)
		}
	}
}
