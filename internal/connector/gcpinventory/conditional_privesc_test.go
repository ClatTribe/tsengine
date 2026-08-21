package gcpinventory

import (
	"strings"
	"testing"
)

// A condition-gated escalation must be REPORTED and marked, never dropped.
//
// Measured against this code before the fix: the unconditional binding produced one privesc and the
// identical binding carrying an IAM condition produced ZERO. Not a lower-confidence edge — nothing
// at all, so the attack-path page said there was no way for this principal to become admin.
//
// The condition below is satisfied at the time of writing and stays satisfied for years, so the
// escalation it gates is not hypothetical: that principal can call setIamPolicy today. Even a
// condition that were NOT satisfied is worth reporting, because conditions are the thing an attacker
// waits out or arranges — which is exactly why AWS reports the same case as "config-possible;
// validate live" rather than staying quiet.
//
// §10 permits saying "we could not resolve this". It does not permit silence.
func TestConditionGatedEscalationIsReportedAsConfigPossible(t *testing.T) {
	const member = "user:eve@corp.example"
	base := RawGCP{
		ProjectID: "p1",
		Members:   []RawGCPMember{{Member: member}},
		RoleDefs: map[string][]string{
			"roles/resourcemanager.projectIamAdmin": {"resourcemanager.projects.setIamPolicy"},
		},
	}

	gated := base
	gated.Bindings = []RawGCPBinding{{
		Role:      "roles/resourcemanager.projectIamAdmin",
		Members:   []string{member},
		Condition: `request.time < timestamp("2030-01-01T00:00:00Z")`,
	}}
	inv := Build(gated)
	if len(inv.Privescs) != 1 {
		t.Fatalf("a condition-gated escalation to project admin produced %d privescs, want 1.\n"+
			"Dropping it entirely is how the attack-path page came to report no route to admin for a "+
			"principal that can call setIamPolicy right now.", len(inv.Privescs))
	}
	if inv.Privescs[0].Condition == "" {
		t.Error("the edge must SAY it is condition-gated — reporting it as definite is the opposite " +
			"overclaim and equally wrong")
	}
	if !strings.Contains(inv.Privescs[0].Condition, "config-possible") {
		t.Errorf("condition wording should match the AWS path so both clouds make the same claim, got %q",
			inv.Privescs[0].Condition)
	}

	// The control: same role, no condition — definite, and NOT marked.
	plain := base
	plain.Bindings = []RawGCPBinding{{Role: "roles/resourcemanager.projectIamAdmin", Members: []string{member}}}
	inv2 := Build(plain)
	if len(inv2.Privescs) != 1 {
		t.Fatalf("unconditional control: want 1 privesc, got %d", len(inv2.Privescs))
	}
	if inv2.Privescs[0].Condition != "" {
		t.Errorf("an UNCONDITIONAL escalation must not be softened to config-possible — that would "+
			"make every edge conditional and the distinction worthless, got %q", inv2.Privescs[0].Condition)
	}

	// And a principal with no escalating permission still gets nothing: the fix must not turn
	// "permitted, conditionally" into "everyone might escalate".
	//
	// NOT roles/viewer, which was the first fixture here and was wrong: viewer grants read
	// permissions, and ViewExistingAPIKeys is one of the 23 catalogued techniques precisely
	// because an existing API key can carry more privilege than the reader has. The engine was
	// right and the fixture was wrong — worth recording, since a fixture that disagrees with a
	// correct detector is the easiest way to argue yourself into breaking one.
	none := base
	none.Bindings = []RawGCPBinding{{
		Role: "roles/custom.logwriter", Members: []string{member},
		Condition: `request.time < timestamp("2030-01-01T00:00:00Z")`,
	}}
	none.RoleDefs = map[string][]string{"roles/custom.logwriter": {"logging.logEntries.create"}}
	if inv3 := Build(none); len(inv3.Privescs) != 0 {
		t.Errorf("a condition-gated role granting only log-write is not an escalation path, got %d privescs: %+v",
			len(inv3.Privescs), inv3.Privescs)
	}
}
