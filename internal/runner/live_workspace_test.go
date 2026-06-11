package runner

import (
	"context"
	"errors"
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
	src := &LiveWorkspaceSource{Store: st, Tokens: tokStub{}, Fetchers: map[string]Fetcher{platform.ConnGWorkspace: f}}

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

// domainFetcher returns a workspace whose users span a domain, no Domains set — exactly
// what a provider user-fetch yields (accounts, not the sending domains' DNS).
type domainFetcher struct{}

func (domainFetcher) Fetch(context.Context, string, time.Time) (operate.Workspace, error) {
	return operate.Workspace{Org: "acme", Users: []operate.User{
		{Email: "alice@acme.com", MFA: true}, {Email: "bob@acme.com", MFA: true},
	}}, nil
}

// fakeTXT is a deterministic DNS resolver (operate.Resolver) for the enrichment test.
type fakeTXT map[string][]string

func (f fakeTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f[name]; ok {
		return r, nil
	}
	return nil, errors.New("nxdomain")
}

func TestLiveWorkspaceSource_EnrichesEmailAuthFromDNS(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGWorkspace, SecretRef: "sealed"})
	dns := fakeTXT{
		"_dmarc.acme.com":            {"v=DMARC1; p=reject"},
		"acme.com":                   {"v=spf1 include:_spf.google.com ~all"},
		"google._domainkey.acme.com": {"v=DKIM1; p=abc"},
	}
	src := &LiveWorkspaceSource{
		Store: st, Tokens: tokStub{},
		Fetchers:  map[string]Fetcher{platform.ConnGWorkspace: domainFetcher{}},
		EmailAuth: &operate.EmailAuth{Resolver: dns},
	}
	ws, err := src.Workspace(ctx, platform.Asset{TenantID: "t1", ConnectionID: "c1", Type: WorkspaceType, Target: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	// The live source derived acme.com from the users and resolved its DNS posture.
	if len(ws.Domains) != 1 || ws.Domains[0].Name != "acme.com" {
		t.Fatalf("expected acme.com enriched from users, got %+v", ws.Domains)
	}
	if d := ws.Domains[0]; d.DMARC != "reject" || !d.SPF || !d.DKIM {
		t.Fatalf("email-auth not resolved from DNS: %+v", d)
	}
}

func TestLiveWorkspaceSource_NoEnricherLeavesDomainsEmpty(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGWorkspace, SecretRef: "sealed"})
	src := &LiveWorkspaceSource{Store: st, Tokens: tokStub{}, Fetchers: map[string]Fetcher{platform.ConnGWorkspace: domainFetcher{}}}
	ws, err := src.Workspace(ctx, platform.Asset{TenantID: "t1", ConnectionID: "c1", Type: WorkspaceType, Target: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.Domains) != 0 {
		t.Errorf("without an enricher, domains stay empty (today's behavior), got %+v", ws.Domains)
	}
}

func TestLiveWorkspaceSource_MissingConnectionErrors(t *testing.T) {
	src := &LiveWorkspaceSource{Store: store.NewMemory(), Tokens: tokStub{}, Fetchers: map[string]Fetcher{platform.ConnGWorkspace: &fetcherStub{}}}
	_, err := src.Workspace(context.Background(), platform.Asset{TenantID: "t1", ConnectionID: "ghost", Type: WorkspaceType})
	if err == nil {
		t.Error("a workspace asset whose connection is missing should error")
	}
}

func TestLiveWorkspaceSource_UnknownProviderErrors(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnM365, SecretRef: "x"})
	// only a gworkspace fetcher registered → an m365 connection has no fetcher
	src := &LiveWorkspaceSource{Store: st, Tokens: tokStub{}, Fetchers: map[string]Fetcher{platform.ConnGWorkspace: &fetcherStub{}}}
	if _, err := src.Workspace(ctx, platform.Asset{TenantID: "t1", ConnectionID: "c1", Type: WorkspaceType}); err == nil {
		t.Error("a provider with no registered fetcher should error")
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
