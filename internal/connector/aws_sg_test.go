package connector

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// An approved sg_revoke_open_ingress action reaches the writer with the group id and the port —
// the port surviving a JSON round trip as a float64 — and Preflight refuses a malformed group or a
// missing write path BEFORE anyone approves it.
func TestAWS_Apply_SGRevokeOpenIngress(t *testing.T) {
	w := &fakeS3Writer{}
	a := NewAWS("", "", "")
	a.Writer = w
	act := platform.Action{ID: "act-sg", Payload: map[string]any{
		"remediation_type": "sg_revoke_open_ingress", "target": "sg-0abc12345", "port": float64(22),
	}}
	if err := a.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatalf("approved revoke should apply: %v", err)
	}
	if len(w.revoked) != 1 || w.revoked[0] != "sg-0abc12345:22" {
		t.Errorf("expected RevokeOpenIngress(sg-0abc12345, 22), got %v", w.revoked)
	}
	// No port → 0 (every world-open rule).
	noPort := platform.Action{ID: "act-sg2", Payload: map[string]any{"remediation_type": "sg_revoke_open_ingress", "target": "sg-0abc12345"}}
	_ = a.Apply(context.Background(), platform.Connection{}, "tok", noPort)
	if len(w.revoked) != 2 || w.revoked[1] != "sg-0abc12345:0" {
		t.Errorf("no port must pass 0: %v", w.revoked)
	}

	bad := platform.Action{ID: "act-bad", Payload: map[string]any{"remediation_type": "sg_revoke_open_ingress", "target": "the default group"}}
	if err := a.Preflight(platform.Connection{}, bad); err == nil || !strings.Contains(err.Error(), "names no security group id") {
		t.Errorf("a non-id target must be refused at preflight: %v", err)
	}
	if err := a.Apply(context.Background(), platform.Connection{}, "tok", bad); err == nil || len(w.revoked) != 2 {
		t.Errorf("apply must refuse the same way and never reach the writer: %v %v", err, w.revoked)
	}
	none := NewAWS("", "", "")
	if err := none.Preflight(platform.Connection{}, act); err == nil || !strings.Contains(err.Error(), "no live AWS write path") {
		t.Errorf("no writer must be named before approval: %v", err)
	}
}
