package cloudprobe

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
)

func fixedNow() string { return "2026-08-23T00:00:00Z" }

func TestProber_MapsProviderDecisionsToVerdicts(t *testing.T) {
	tuple := [3]string{"role/app", "iam:PassRole", "role/admin"}
	sim := FakeSimulator{
		Allow: map[[3]string]string{tuple: "matched allow statement"},
		Deny:  map[[3]string]bool{{"role/app", "s3:DeleteBucket", "arn:bkt"}: true},
	}
	p := &Prober{Sim: sim, Now: fixedNow}

	// ALLOW
	got, err := p.CanPerform(context.Background(), tuple[0], tuple[1], tuple[2])
	if err != nil || got.Verdict != cloudagent.VerdictAllow {
		t.Fatalf("allow tuple must map to VerdictAllow, got %v err=%v", got.Verdict, err)
	}
	if got.ProbedAt != fixedNow() || got.Detail == "" {
		t.Errorf("verdict must carry ProbedAt + detail, got %+v", got)
	}
	// DENY
	d, _ := p.CanPerform(context.Background(), "role/app", "s3:DeleteBucket", "arn:bkt")
	if d.Verdict != cloudagent.VerdictDeny {
		t.Errorf("explicit deny must map to VerdictDeny, got %v", d.Verdict)
	}
	// UNKNOWN — no matching rule is NOT a deny (§10).
	u, _ := p.CanPerform(context.Background(), "role/app", "iam:PassRole", "role/other")
	if u.Verdict != cloudagent.VerdictUnknown {
		t.Errorf("an unmatched tuple must be UNKNOWN, never DENY, got %v", u.Verdict)
	}
}

// The no-permission case is UNKNOWN with a reason — the honest degradation, not a silent deny.
func TestProber_NoSimulatePermissionIsUnknownWithReason(t *testing.T) {
	p := &Prober{Sim: FakeSimulator{NoPerm: true}, Now: fixedNow}
	got, _ := p.CanPerform(context.Background(), "a", "b", "c")
	if got.Verdict != cloudagent.VerdictUnknown || got.Why == "" {
		t.Fatalf("no simulate permission must be UNKNOWN with a Why, got %+v", got)
	}
}

// The adapter must satisfy the agent's SDK-free interface (compile-time in cloudprobe.go; asserted
// here at runtime too).
func TestProber_SatisfiesExploitProber(t *testing.T) {
	var _ cloudagent.ExploitProber = &Prober{Sim: FakeSimulator{}}
}
