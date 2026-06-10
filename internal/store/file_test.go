package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestFile_SurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "platform.json")

	// write some state through the File store
	f1, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f1.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = f1.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, SecretRef: "vault:tok"})
	_ = f1.PutFinding(ctx, "t1", types.Finding{ID: "f1", Severity: types.SeverityHigh})
	_ = f1.PutAction(ctx, platform.Action{ID: "a1", TenantID: "t1", Tier: 2, Status: platform.ActPendingApproval})
	_ = f1.UpsertControlState(ctx, platform.ControlState{TenantID: "t1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlGap})

	// reopen from disk → all of it must come back
	f2, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if tn, err := f2.GetTenant(ctx, "t1"); err != nil || tn.Name != "Acme" {
		t.Errorf("tenant lost on reopen: %+v %v", tn, err)
	}
	fs, _ := f2.ListFindings(ctx, "t1", FindingFilter{})
	if len(fs) != 1 || fs[0].ID != "f1" {
		t.Errorf("findings lost on reopen: %+v", fs)
	}
	pend, _ := f2.PendingApprovals(ctx, "t1")
	if len(pend) != 1 || pend[0].ID != "a1" {
		t.Errorf("pending action lost on reopen: %+v", pend)
	}
	post, _ := f2.Posture(ctx, "t1", "soc2")
	if len(post) != 1 || post[0].State != platform.ControlGap {
		t.Errorf("control state lost on reopen: %+v", post)
	}
}

func TestFile_TenantIsolationPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.json")
	f, _ := OpenFile(path)
	_ = f.PutFinding(ctx, "t1", types.Finding{ID: "a"})
	_ = f.PutFinding(ctx, "t2", types.Finding{ID: "b"})

	reopened, _ := OpenFile(path)
	t1, _ := reopened.ListFindings(ctx, "t1", FindingFilter{})
	if len(t1) != 1 || t1[0].ID != "a" {
		t.Fatalf("t1 isolation broke across persistence: %+v", t1)
	}
	for _, x := range t1 {
		if x.ID == "b" {
			t.Fatal("ISOLATION: t1 saw t2's finding after reopen")
		}
	}
}

func TestFile_FreshWhenAbsent(t *testing.T) {
	f, err := OpenFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("opening an absent path should create a fresh store, got %v", err)
	}
	if fs, _ := f.ListFindings(context.Background(), "t", FindingFilter{}); len(fs) != 0 {
		t.Errorf("fresh store should be empty, got %d", len(fs))
	}
}

// the File store must satisfy the Store interface (compile-time check)
var _ Store = (*File)(nil)
