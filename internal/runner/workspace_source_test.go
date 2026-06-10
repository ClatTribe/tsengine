package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestSnapshotSource_LoadsFromAssetMeta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ws.json")
	snap := `{"provider":"gworkspace","org":"acme","users":[{"email":"ceo@acme","super_admin":true,"mfa":false}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}

	ws, err := SnapshotSource{}.Workspace(context.Background(), platform.Asset{
		Type: WorkspaceType, Target: "acme", Meta: map[string]string{SnapshotKey: path},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ws.Org != "acme" || len(ws.Users) != 1 || ws.Users[0].Email != "ceo@acme" {
		t.Fatalf("snapshot not loaded: %+v", ws)
	}

	// end-to-end through the OperateRunner → grounded finding
	or := &OperateRunner{Source: SnapshotSource{}}
	fs, err := or.Scan(context.Background(), platform.Asset{Type: WorkspaceType, Target: "acme", Meta: map[string]string{SnapshotKey: path}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "operate::admin-without-mfa" {
		t.Errorf("end-to-end operate run wrong: %+v", fs)
	}
}

func TestSnapshotSource_MissingMetaErrors(t *testing.T) {
	_, err := SnapshotSource{}.Workspace(context.Background(), platform.Asset{Type: WorkspaceType, Target: "x"})
	if err == nil {
		t.Error("a workspace asset with no snapshot path should error, not run on empty")
	}
}
