package apiauthz

import (
	"context"
	"testing"
)

// TestProposeOperations_MassNeedsBody: a proposed mass_assignment op is only testable if it carries a
// write BODY (Run writes op.Body; evaluateMassAssignment needs the privileged marker to persist on
// read-back). The proposer advertised "mass" as a class but its output schema had no body field, so
// every proposed mass op had Body:"" — a guaranteed no-op that can never detect a mass-assignment
// bypass AND wastes a live write request. A mass op with a body must be kept (body intact); one without
// a body (or marker) must be DROPPED, not emitted as a dead test.
func TestProposeOperations_MassNeedsBody(t *testing.T) {
	llm := fakeLLM{out: `[
	  {"method":"POST","url":"https://api.x/users","class":"mass","marker":"admin","body":"{\"name\":\"me\",\"role\":\"admin\"}"},
	  {"method":"PATCH","url":"https://api.x/profile","class":"mass","marker":"admin"}
	]`}
	ops, err := ProposeOperations(context.Background(), llm, nil, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 {
		t.Fatalf("want 1 testable mass op (the bodyless one dropped), got %d: %+v", len(ops), ops)
	}
	if ops[0].Body == "" {
		t.Errorf("proposed mass op lost its write body — the mass-assignment test would be a no-op: %+v", ops[0])
	}
	if ops[0].Marker != "admin" {
		t.Errorf("proposed mass op lost its marker: %+v", ops[0])
	}
}
