package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestOkta_OAuthURL(t *testing.T) {
	o := NewOkta("https://dev-1.okta.com/", "cid", "sec")
	u := o.OAuthURL("st8", "https://app/cb")
	for _, want := range []string{
		"https://dev-1.okta.com/oauth2/v1/authorize", "client_id=cid", "state=st8",
		"okta.users.read", "okta.factors.read",
	} {
		if !contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestOkta_ExchangeReturnsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/v1/token" {
			t.Errorf("unexpected token path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-xyz"}`))
	}))
	defer srv.Close()
	o := &Okta{OrgURL: srv.URL, ClientID: "cid", ClientSecret: "sec", HTTP: srv.Client()}
	c, err := o.Exchange(context.Background(), "code", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != platform.ConnOkta || c.SecretRef != "tok-xyz" || c.Status != platform.ConnActive {
		t.Errorf("exchange returned wrong connection: %+v", c)
	}
}

func TestOkta_ExchangeFailsWithoutToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	o := &Okta{OrgURL: srv.URL, ClientID: "cid", ClientSecret: "sec", HTTP: srv.Client()}
	if _, err := o.Exchange(context.Background(), "bad", "https://app/cb"); err == nil {
		t.Error("a token-less exchange should error")
	}
}

func TestOkta_DiscoverYieldsWorkspaceAsset(t *testing.T) {
	o := NewOkta("https://dev-1.okta.com", "a", "b")
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Account: "acme-okta"}
	assets, err := o.Discover(context.Background(), conn, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Type != "workspace" || assets[0].ConnectionID != "c1" || assets[0].Target != "acme-okta" {
		t.Fatalf("workspace asset wrong: %+v", assets)
	}
}

func TestOkta_RegistryResolves(t *testing.T) {
	r := NewRegistry(NewGitHub("a", "b"), NewOkta("https://dev-1.okta.com", "c", "d"))
	if _, err := r.Get(platform.ConnOkta); err != nil {
		t.Errorf("okta should resolve: %v", err)
	}
}
