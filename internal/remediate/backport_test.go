package remediate

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/backport"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func ids() func() string {
	n := 0
	return func() string { n++; return "act-" + strconv.Itoa(n) }
}

func srcLines(s string) []string { return strings.Split(strings.TrimPrefix(s, "\n"), "\n") }

// The merged fix: stop shelling out with user input.
func shellFixHunk() backport.Hunk {
	return backport.Hunk{
		File:    "run.go",
		Before:  []string{"func run(userInput string) {"},
		Removed: []string{"\tcmd := exec.Command(\"sh\", \"-c\", userInput)"},
		Added:   []string{"\tcmd := exec.Command(\"echo\", userInput)"},
		After:   []string{"\tcmd.Run()"},
	}
}

const vulnerableBranch = `
package main

func helper() {}

func run(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
`

const fixedBranch = `
package main

func run(userInput string) {
	cmd := exec.Command("echo", userInput)
	cmd.Run()
}
`

const unrelatedBranch = `
package main

func run(userInput string) {
	println(userInput)
}
`

const reformattedBranch = `
package main

func run(userInput string) {
	cmd  :=  exec.Command( "sh" , "-c" , userInput )
	cmd.Run()
}
`

func srcAction() platform.Action {
	return platform.Action{
		TenantID: "ten-1", FindingID: "f-1", FindingKeys: []string{"semgrep::shell-injection|run.go:6"},
		ConnectionID: "conn-1",
	}
}

// A still-vulnerable branch where the code above the bug moved: the patch
// relocates and a reviewable PR is proposed carrying the patched content.
func TestPlanBackports_VulnerableBranchGetsAPR(t *testing.T) {
	plans := PlanBackports(srcAction(), shellFixHunk(),
		[]BranchFile{{Branch: "release/2.3", Path: "run.go", Lines: srcLines(vulnerableBranch)}}, ids())
	if len(plans) != 1 {
		t.Fatalf("want 1 plan, got %d", len(plans))
	}
	p := plans[0]
	if p.Action == nil || p.Action.Kind != platform.ActOpenPR {
		t.Fatalf("a relocatable fix should propose a PR, got %+v", p)
	}
	if p.Action.Tier != tierOpenPR {
		t.Errorf("a code-fix PR is reversible → tier %d, got %d", tierOpenPR, p.Action.Tier)
	}
	content, _ := p.Action.Payload["content"].(string)
	if strings.Contains(content, `"sh", "-c"`) {
		t.Error("the PR content must not still contain the vulnerable call")
	}
	if !strings.Contains(content, `"echo"`) {
		t.Error("the PR content should contain the fix")
	}
	if p.Action.Payload["branch"] != "release/2.3" {
		t.Errorf("the action must name the target branch, got %v", p.Action.Payload["branch"])
	}
	// Grounding: the originating finding rides along so the fix stays auditable
	// and re-testable.
	if p.Action.FindingID != "f-1" || len(p.Action.FindingKeys) != 1 {
		t.Errorf("the backport action must cite the originating finding: %+v", p.Action)
	}
}

// A branch that already has the fix must produce NO action. Re-applying a
// security patch is a real, damaging failure mode.
func TestPlanBackports_AlreadyFixedBranchGetsNoAction(t *testing.T) {
	plans := PlanBackports(srcAction(), shellFixHunk(),
		[]BranchFile{{Branch: "release/3.0", Path: "run.go", Lines: srcLines(fixedBranch)}}, ids())
	if plans[0].Verdict != backport.VerdictAlreadyApplied {
		t.Fatalf("verdict = %q (%s), want already_applied", plans[0].Verdict, plans[0].Reason)
	}
	if plans[0].Action != nil {
		t.Errorf("an already-fixed branch must get NO action, got %+v", plans[0].Action)
	}
}

// A branch that never had the vulnerable code path gets no action either.
func TestPlanBackports_UnaffectedBranchGetsNoAction(t *testing.T) {
	plans := PlanBackports(srcAction(), shellFixHunk(),
		[]BranchFile{{Branch: "release/1.0", Path: "run.go", Lines: srcLines(unrelatedBranch)}}, ids())
	if plans[0].Verdict != backport.VerdictNotApplicable {
		t.Fatalf("verdict = %q (%s), want not_applicable", plans[0].Verdict, plans[0].Reason)
	}
	if plans[0].Action != nil {
		t.Errorf("an unaffected branch must get NO action, got %+v", plans[0].Action)
	}
}

// THE KEY SAFETY PROPERTY: when the patch cannot be placed mechanically we file
// a ticket for a human/agent to adapt it — we never open a PR with a patch we
// could not place (§10: never guess).
func TestPlanBackports_UnplaceablePatchNeverBecomesAPR(t *testing.T) {
	plans := PlanBackports(srcAction(), shellFixHunk(),
		[]BranchFile{{Branch: "release/2.0", Path: "run.go", Lines: srcLines(reformattedBranch)}}, ids())
	p := plans[0]
	if p.Verdict != backport.VerdictNeedsAdaptation {
		t.Fatalf("verdict = %q (%s), want needs_adaptation", p.Verdict, p.Reason)
	}
	if p.Action == nil {
		t.Fatal("an affected-but-unplaceable branch should still be surfaced for adaptation")
	}
	if p.Action.Kind == platform.ActOpenPR {
		t.Fatal("must NOT open a PR for a patch that could not be placed")
	}
	if p.Action.Kind != platform.ActFileTicket {
		t.Errorf("want a ticket for adaptation, got %q", p.Action.Kind)
	}
	if rb, _ := p.Action.Payload["runbook"].(string); !strings.Contains(rb, "release/2.0") {
		t.Errorf("the runbook should name the branch, got %q", rb)
	}
}

// A realistic fleet: several branches at once, each judged on its own content.
func TestPlanBackports_MixedFleet(t *testing.T) {
	plans := PlanBackports(srcAction(), shellFixHunk(), []BranchFile{
		{Branch: "release/2.3", Path: "run.go", Lines: srcLines(vulnerableBranch)},
		{Branch: "release/3.0", Path: "run.go", Lines: srcLines(fixedBranch)},
		{Branch: "release/1.0", Path: "run.go", Lines: srcLines(unrelatedBranch)},
		{Branch: "release/2.0", Path: "run.go", Lines: srcLines(reformattedBranch)},
	}, ids())
	if len(plans) != 4 {
		t.Fatalf("want a plan per branch, got %d", len(plans))
	}
	var prs, tickets, none int
	for _, p := range plans {
		switch {
		case p.Action == nil:
			none++
		case p.Action.Kind == platform.ActOpenPR:
			prs++
		case p.Action.Kind == platform.ActFileTicket:
			tickets++
		}
		if strings.TrimSpace(p.Reason) == "" {
			t.Errorf("%s: every plan must explain itself", p.Branch)
		}
	}
	if prs != 1 || tickets != 1 || none != 2 {
		t.Errorf("want 1 PR / 1 ticket / 2 no-action, got %d/%d/%d", prs, tickets, none)
	}
	// Action ids must be unique (they are distinct store entities).
	seen := map[string]bool{}
	for _, p := range plans {
		if p.Action == nil {
			continue
		}
		if seen[p.Action.ID] {
			t.Errorf("duplicate action id %q", p.Action.ID)
		}
		seen[p.Action.ID] = true
	}
}

func TestPlanBackports_NoBranchesIsNoOp(t *testing.T) {
	if got := PlanBackports(srcAction(), shellFixHunk(), nil, ids()); len(got) != 0 {
		t.Errorf("no branches → no plans, got %+v", got)
	}
}
