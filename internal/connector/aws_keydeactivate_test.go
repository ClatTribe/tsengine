package connector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// aws_key_deactivate is a LIVE write path: Apply reaches the writer with the key id from the
// action's target; Preflight refuses an action with no key id or no writer, so a human at the desk
// is never asked to approve something that could not run.
func TestAWSApply_KeyDeactivateReachesTheWriterAndPreflightRefusesTheUnrunnable(t *testing.T) {
	w := &fakeS3Writer{}
	a := &AWS{Writer: w}
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive}
	act := platform.Action{ID: "act-1", Kind: platform.ActApplyConfig,
		Payload: map[string]any{"remediation_type": "aws_key_deactivate", "target": " AKIAIOSFODNN7EXAMPLE "}}
	if err := a.Apply(context.Background(), conn, "", act); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(w.deactivated) != 1 || w.deactivated[0] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("writer received %v", w.deactivated)
	}

	// A denied write surfaces as itself — never "applied".
	w.err = errors.New("AccessDenied: iam:UpdateAccessKey")
	if err := a.Apply(context.Background(), conn, "", act); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("a denied deactivation must surface: %v", err)
	}

	noKey := platform.Action{ID: "act-2", Kind: platform.ActApplyConfig, Payload: map[string]any{"remediation_type": "aws_key_deactivate"}}
	if err := a.Preflight(conn, noKey); err == nil || !strings.Contains(err.Error(), "names no access key id") {
		t.Errorf("preflight must refuse an action with no key id: %v", err)
	}
	if err := (&AWS{}).Preflight(conn, act); err == nil || !strings.Contains(err.Error(), "no live AWS write path") {
		t.Errorf("preflight must refuse when no writer is configured: %v", err)
	}
}
