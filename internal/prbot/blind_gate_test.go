package prbot

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func crit(endpoint string) types.Finding {
	return types.Finding{
		ID: "f1", RuleID: "gitleaks::aws-key", Severity: types.SeverityCritical,
		Title: "AWS key committed", Endpoint: endpoint,
	}
}

// A merge gate that cannot see the diff must not report a pass.
//
// Every finding is matched against the PR's changed lines, so an empty changed-file list skips all
// of them and the check returned "success" with the summary "no new security findings on the changed
// lines ✅" — in green, with a tick, on a pull request where the gate had not seen a single line.
// The action exited 0 and the merge proceeded.
//
// Zero changed files is not a pull request. It is a diff we failed to obtain: a rate-limited API, a
// token without pull_requests:read, a fork PR, or a CI step that errored and posted an empty list.
func TestBuild_NoChangedFilesIsNotAPass(t *testing.T) {
	r := Build([]types.Finding{crit("src/main.go:42")}, nil, types.SeverityHigh)

	if r.Conclusion == "success" {
		t.Fatal("a check that inspected nothing reported success — the exact green tick that let a " +
			"critical finding through a gate which never saw the diff")
	}
	if r.Conclusion != "neutral" {
		t.Errorf("want neutral (informational, not a pass), got %q", r.Conclusion)
	}
	if strings.Contains(r.Summary, "✅") {
		t.Errorf("the summary must not read as a clean result: %q", r.Summary)
	}
	if !strings.Contains(r.Summary, "NOTHING") || !strings.Contains(r.Summary, "pull_requests: read") {
		t.Errorf("the summary must say nothing was checked AND how to fix it — a developer cannot act "+
			"on %q", r.Summary)
	}
}

// Not a failure, deliberately. This is a broken pipeline, not a discovered vulnerability, and
// blocking every merge on a transient API error gets the whole check switched off — which costs
// more than it saves.
func TestBuild_NoChangedFilesDoesNotBlockTheMerge(t *testing.T) {
	if r := Build([]types.Finding{crit("src/main.go:42")}, nil, types.SeverityHigh); r.Conclusion == "failure" {
		t.Error("a missing diff must not gate the merge")
	}
}

// Files supplied but with no changed LINES is a different case and stays a pass: a PR that only
// deletes files or touches binaries legitimately has nothing to comment on, and the caller did
// supply the diff.
func TestBuild_FilesWithNoLinesIsStillAPass(t *testing.T) {
	changed := []ChangedFile{{Path: "docs/old.md", Lines: map[int]bool{}}}
	r := Build([]types.Finding{crit("src/main.go:42")}, changed, types.SeverityHigh)
	if r.Conclusion != "success" {
		t.Errorf("the diff WAS supplied and nothing in it is commentable — that is a real pass, got %q",
			r.Conclusion)
	}
}

// And the gate still gates: a critical on a line this PR actually changed fails the check.
func TestBuild_StillBlocksOnAChangedLine(t *testing.T) {
	changed := []ChangedFile{{Path: "src/main.go", Lines: map[int]bool{42: true}}}
	r := Build([]types.Finding{crit("src/main.go:42")}, changed, types.SeverityHigh)
	if r.Conclusion != "failure" {
		t.Fatalf("a critical on a changed line must block the merge, got %q — the fix must not become "+
			"a way to make the gate permissive", r.Conclusion)
	}
}
