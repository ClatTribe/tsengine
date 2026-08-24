package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// TestCloudCredentialFailure_ReachesTheArtifactWithItsCause is the consumer-level acceptance for
// ADR 0031 D1: a cloud scanner that fails to authenticate (the canonical prowler/scoutsuite
// failure) must land in ToolsFailed carrying the CAUSE, so the pass degrades and every absence-
// consumer (detect.Reconcile, retest.Verify, grc.RefreshEvidence) refuses. Before the exit
// contract, this exact failure returned err=nil/findings=0 — a clean estate nobody looked at.
//
// The downstream refusals are pinned by their own executing tests
// (runner/detect_loop_test.go TestRescanTenant_DegradedPassNeverResolves + the grc/retest twins);
// this test pins the CLOUD-SPECIFIC entry into that machinery: the wrapper's error text survives
// to the artifact.
func TestCloudCredentialFailure_ReachesTheArtifactWithItsCause(t *testing.T) {
	sink := &failureSink{}
	ctx := withFailureSink(context.Background(), sink)

	credsErr := errors.New("prowler: exit status 1: CRITICAL: Unable to authenticate with AWS — " +
		"check the forwarded credentials")
	dispatches := []asset.Dispatch{{Tool: stubTool{name: "prowler"}}}
	_, fired, _ := executeAll(ctx, dispatches, failingTextDispatcher{err: credsErr})

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 recorded failure, got %d (%+v)", len(got), got)
	}
	if got[0].Tool != "prowler" {
		t.Errorf("failure must name the tool, got %+v", got[0])
	}
	if !strings.Contains(got[0].Reason, "authenticate") {
		t.Errorf("the artifact must carry WHY (the operator reads this in the degraded banner): %+v", got[0])
	}
	for _, f := range fired {
		if f == "prowler" {
			t.Error("a failed scanner must not appear in anchors_fired")
		}
	}
}

// failingTextDispatcher fails EVERY dispatch with the same pre-built error (unlike
// failingDispatcher, which synthesizes its own) so the test controls the exact cause text.
type failingTextDispatcher struct{ err error }

func (d failingTextDispatcher) Execute(_ context.Context, _ string, _ tool.Args) (tool.Result, error) {
	return tool.Result{}, d.err
}
