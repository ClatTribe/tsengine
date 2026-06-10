package connector

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestGWorkspace_OAuthURL(t *testing.T) {
	g := NewGWorkspace("cid", "sec")
	u := g.OAuthURL("st8", "https://app/cb")
	for _, want := range []string{"client_id=cid", "state=st8", "o/oauth2/v2/auth", "admin.directory.user", "access_type=offline"} {
		if !contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestGWorkspace_DiscoverYieldsWorkspaceAsset(t *testing.T) {
	g := NewGWorkspace("a", "b")
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGWorkspace, Account: "acme.example"}
	assets, err := g.Discover(context.Background(), conn, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("want exactly one workspace asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "workspace" || a.ConnectionID != "c1" || a.TenantID != "t1" || a.Target != "acme.example" {
		t.Errorf("workspace asset wrong: %+v", a)
	}
}

func TestGWorkspace_WatchIsNoop(t *testing.T) {
	g := NewGWorkspace("a", "b")
	trigs, err := g.Watch(context.Background(), platform.Connection{}, []byte(`{}`))
	if err != nil || len(trigs) != 0 {
		t.Errorf("watch should be a no-op for scheduled posture: %v %v", trigs, err)
	}
}

func TestGWorkspace_RegistryResolves(t *testing.T) {
	r := NewRegistry(NewGitHub("a", "b"), NewGWorkspace("c", "d"))
	if _, err := r.Get(platform.ConnGWorkspace); err != nil {
		t.Errorf("gworkspace should resolve: %v", err)
	}
}
