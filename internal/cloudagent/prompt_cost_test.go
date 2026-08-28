package cloudagent

import (
	"strings"
	"testing"
)

// TestPromptDeclaresLiveUnavailable covers a COST property that is also an honesty one. The rules
// tell the agent to confirm a flag-dependent severity with get_resource(id, live:true). When no
// live reader is wired that answers COULD NOT CHECK every single time — so the agent spends one
// call PER CROWN JEWEL discovering a fact the harness knew before the run started. On an account
// with 11 jewels that is 11 turns of a ~56-turn budget bought for nothing, and turn budget is the
// binding constraint: the all-fixes run exceeded 1800s without finishing.
//
// Stating it up front must NOT weaken the disclosure — the agent is still told to record that the
// flag was unconfirmed, so the honesty rule survives the saving.
func TestPromptDeclaresLiveUnavailable(t *testing.T) {
	cc := &Context{Snap: groundableFixture()} // no Live reader wired
	p := buildPrompt(cc, nil)

	if !strings.Contains(p, "LIVE RE-READ IS NOT CONFIGURED") {
		t.Error("with no live reader the prompt does not say so, so the agent must spend a call per\njewel discovering it — budget the run does not have")
	}
	if !strings.Contains(p, "could not be live-confirmed") {
		t.Error("the saving removed the DISCLOSURE too: the agent must still record that the flag\ncame from the snapshot and was not live-confirmed")
	}
}

// TestPromptStatesRecordIssueGroundsIndependently pins the other half of the cost fix. record_issue
// runs validatePath itself, so a path find_paths returned is already groundable; the old flow told
// the agent to "verify each candidate with find_paths / blast_radius", buying a redundant call per
// jewel for a check the harness performs anyway.
func TestPromptStatesRecordIssueGroundsIndependently(t *testing.T) {
	p := buildPrompt(&Context{Snap: groundableFixture()}, nil)

	if !strings.Contains(p, "record_issue VALIDATES THE PATH ITSELF") {
		t.Error("the prompt does not tell the agent that record_issue grounds the path itself, so it\nwill keep paying for a confirmation the harness already does")
	}
	// The claim must be TRUE, not just present: validatePath is what makes it so.
	snap := groundableFixture()
	path := []string{"internet",
		"arn:aws:ec2:us-east-1:123456789012:instance/pub-1",
		"arn:aws:iam::123456789012:role/reader-1",
		"arn:aws:s3:::crownjewel-1"}
	if err := validatePath(snap, path, path[len(path)-1]); err != nil {
		t.Errorf("the prompt promises record_issue grounds a find_paths path, but validatePath rejects\none: %v — the instruction would send the agent into rejections", err)
	}
}
