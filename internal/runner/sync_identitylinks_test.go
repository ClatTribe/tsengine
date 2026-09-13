package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/identitylinks"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The pass fetches the person → GitHub join inputs through the onboarded GitHub connection (org and
// token from the connection, repositories from the assets) and stores them; with nothing connected
// that could assert a link, nothing is stored.
func TestSyncIdentityLinks_FetchesThroughTheConnectionAndStores(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-tok" {
			http.Error(w, "no token", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/orgs/acme/members":
			if r.URL.Query().Get("role") == "admin" {
				w.Write([]byte(`[{"login":"ada-acme","id":1}]`))
			} else {
				w.Write([]byte(`[{"login":"ada-acme","id":1},{"login":"bob","id":2}]`))
			}
		case "/repos/acme/shop/collaborators":
			w.Write([]byte(`[{"login":"bob","permissions":{"admin":false,"push":true}}]`))
		case "/graphql":
			w.Write([]byte(`{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"pageInfo":{"hasNextPage":false},"nodes":[{"user":{"login":"bob"},"samlIdentity":{"nameId":"bob@acme.io"}}]}}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive, Account: "acme", SecretRef: "sealed"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", ConnectionID: "c1", Type: "repository", Target: "acme/shop", Meta: map[string]string{"full_name": "acme/shop"}})
	svc := &Service{Store: st, Tokens: idTokens{tok: "gh-tok"}, NewID: func() string { return "x" },
		IdentityLinkOpts: &identitylinks.Options{GitHubAPIBase: srv.URL, HTTP: srv.Client()}}

	if !svc.syncIdentityLinks(ctx, "t1") {
		t.Fatal("a connected GitHub org must produce a stored link set")
	}
	set, ok, err := st.GetIdentityLinks(ctx, "t1")
	if err != nil || !ok {
		t.Fatalf("not stored: ok=%v err=%v", ok, err)
	}
	if len(set.Links) != 1 || set.Links[0].Login != "bob" || set.Links[0].Email != "bob@acme.io" {
		t.Errorf("links: %+v", set.Links)
	}
	var orgOwner, repoPush bool
	for _, c := range set.Controls {
		if c.Login == "ada-acme" && c.Repo == "" && c.Admin {
			orgOwner = true
		}
		if c.Login == "bob" && c.Repo == "shop" && !c.Admin {
			repoPush = true
		}
	}
	if !orgOwner || !repoPush {
		t.Errorf("controls must carry the org owner and the repository collaborator: %+v", set.Controls)
	}
	if set.Unread[identitylinks.SourceOktaSCIM] != "no Okta connection" {
		t.Errorf("the missing Okta source must be named: %v", set.Unread)
	}

	// Nothing connected → nothing stored (a set with zero links would read as "nobody controls code").
	st2 := store.NewMemory()
	_ = st2.PutTenant(ctx, platform.Tenant{ID: "t2"})
	svc2 := &Service{Store: st2, Tokens: idTokens{tok: "x"}, NewID: func() string { return "x" }, IdentityLinkOpts: &identitylinks.Options{}}
	if svc2.syncIdentityLinks(ctx, "t2") {
		t.Error("with no GitHub or Okta connection nothing can be asserted, so nothing should be stored")
	}
	if _, ok, _ := st2.GetIdentityLinks(ctx, "t2"); ok {
		t.Error("a link set was stored for a tenant with nothing connected")
	}
}
