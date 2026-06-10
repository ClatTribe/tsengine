package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// staticWorkspace returns a fixed snapshot for any asset.
type staticWorkspace struct{ ws operate.Workspace }

func (s staticWorkspace) Workspace(context.Context, platform.Asset) (operate.Workspace, error) {
	return s.ws, nil
}

func TestOperateRunner_ProducesGroundedFindings(t *testing.T) {
	ws := operate.Workspace{Org: "acme", Users: []operate.User{
		{Email: "ceo@acme", SuperAdmin: true, MFA: false}, // → critical admin-without-mfa
	}}
	or := &OperateRunner{Source: staticWorkspace{ws}}
	fs, err := or.Scan(context.Background(), platform.Asset{Type: WorkspaceType, Target: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "operate::admin-without-mfa" || fs[0].Endpoint != "ceo@acme" {
		t.Fatalf("operate runner findings wrong: %+v", fs)
	}
	if fs[0].Tool != "operate" {
		t.Errorf("findings should be tagged operate, got %q", fs[0].Tool)
	}
}

// fakeEngine stands in for the sandbox engine runner.
type fakeEngine struct{ called bool }

func (e *fakeEngine) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	e.called = true
	return []types.Finding{{ID: "eng-1", Tool: "nuclei"}}, nil
}

func TestMux_RoutesByAssetType(t *testing.T) {
	eng := &fakeEngine{}
	op := &OperateRunner{Source: staticWorkspace{operate.Workspace{Users: []operate.User{{Email: "a", Admin: true, MFA: false}}}}}
	mux := &MuxRunner{Engine: eng, Workspace: op}
	ctx := context.Background()

	// a repository asset → the sandbox engine
	rf, _ := mux.Scan(ctx, platform.Asset{Type: "repository", Target: "https://github.com/acme/web"})
	if !eng.called || len(rf) != 1 || rf[0].Tool != "nuclei" {
		t.Errorf("repository asset should route to the engine: called=%v %+v", eng.called, rf)
	}

	// a workspace asset → operate
	wf, _ := mux.Scan(ctx, platform.Asset{Type: WorkspaceType, Target: "acme"})
	if len(wf) != 1 || wf[0].Tool != "operate" {
		t.Errorf("workspace asset should route to operate: %+v", wf)
	}
}

func TestMux_MissingBackendErrors(t *testing.T) {
	mux := &MuxRunner{} // neither configured
	if _, err := mux.Scan(context.Background(), platform.Asset{Type: WorkspaceType}); err == nil {
		t.Error("workspace asset with no workspace runner should error")
	}
	if _, err := mux.Scan(context.Background(), platform.Asset{Type: "repository"}); err == nil {
		t.Error("tech asset with no engine should error")
	}
}
