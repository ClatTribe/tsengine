package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// fetcherStub returns a fixed workspace and records the token it was given.
type fetcherStub struct{ gotToken string }

func (f *fetcherStub) Fetch(_ context.Context, token string, _ time.Time) (operate.Workspace, error) {
	f.gotToken = token
	return operate.Workspace{Org: "acme", Users: []operate.User{{Email: "admin@acme", Admin: true, MFA: false}}}, nil
}

type tokStub struct{}

func (tokStub) Resolve(_ context.Context, c platform.Connection) (string, error) {
	return "opened-" + c.SecretRef, nil
}

func TestLiveWorkspaceSource_ResolvesTokenAndFetches(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGWorkspace, SecretRef: "sealed"})
	f := &fetcherStub{}
	src := &LiveWorkspaceSource{Store: st, Tokens: tokStub{}, Fetcher: f}

	ws, err := src.Workspace(ctx, platform.Asset{TenantID: "t1", ConnectionID: "c1", Type: WorkspaceType, Target: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if f.gotToken != "opened-sealed" {
		t.Errorf("source should resolve the connection's vaulted token, got %q", f.gotToken)
	}
	if ws.Org != "acme" || len(ws.Users) != 1 {
		t.Errorf("workspace not fetched: %+v", ws)
	}
}

func TestLiveWorkspaceSource_MissingConnectionErrors(t *testing.T) {
	src := &LiveWorkspaceSource{Store: store.NewMemory(), Tokens: tokStub{}, Fetcher: &fetcherStub{}}
	_, err := src.Workspace(context.Background(), platform.Asset{TenantID: "t1", ConnectionID: "ghost", Type: WorkspaceType})
	if err == nil {
		t.Error("a workspace asset whose connection is missing should error")
	}
}

func TestCompositeSource_PrefersSnapshotElseLive(t *testing.T) {
	ctx := context.Background()
	snap := SnapshotSource{}
	live := &fetcherWorkspaceSource{ws: operate.Workspace{Org: "live"}}
	comp := CompositeSource{Snapshot: snap, Live: live}

	// asset with a snapshot path → snapshot source (which will error on a fake path,
	// proving it was chosen over live)
	_, err := comp.Workspace(ctx, platform.Asset{Type: WorkspaceType, Meta: map[string]string{SnapshotKey: "/no/such/file"}})
	if err == nil || live.called {
		t.Errorf("a snapshot-bearing asset must use the snapshot source, not live (liveCalled=%v err=%v)", live.called, err)
	}

	// asset with no snapshot path → live source
	ws, err := comp.Workspace(ctx, platform.Asset{Type: WorkspaceType, Target: "x"})
	if err != nil || ws.Org != "live" {
		t.Errorf("no-snapshot asset should use live: %+v %v", ws, err)
	}
}

// fetcherWorkspaceSource is a trivial WorkspaceSource for the composite test.
type fetcherWorkspaceSource struct {
	ws     operate.Workspace
	called bool
}

func (f *fetcherWorkspaceSource) Workspace(context.Context, platform.Asset) (operate.Workspace, error) {
	f.called = true
	return f.ws, nil
}
