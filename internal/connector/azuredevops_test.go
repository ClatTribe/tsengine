package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestAzureDevOps_DiscoverReposToAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.URL.Path, "/acme/_apis/git/repositories") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[
			{"id":"r1","name":"api","webUrl":"https://dev.azure.com/acme/Core/_git/api","project":{"name":"Core"},"isDisabled":false},
			{"id":"r2","name":"old","webUrl":"https://dev.azure.com/acme/Core/_git/old","project":{"name":"Core"},"isDisabled":true}
		]}`))
	}))
	defer srv.Close()

	a := NewAzureDevOps("id", "sec", "acme")
	a.APIBase = srv.URL
	assets, err := a.Discover(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 { // disabled repo dropped
		t.Fatalf("want 1 asset, got %d", len(assets))
	}
	got := assets[0]
	if got.Type != "repository" || got.Target != "https://dev.azure.com/acme/Core/_git/api" || got.ConnectionID != "c1" {
		t.Errorf("asset wrong: %+v", got)
	}
	if got.Meta["project"] != "Core" || got.Meta["repo_id"] != "r1" {
		t.Errorf("asset meta wrong: %+v", got.Meta)
	}
}

func TestAzureDevOps_DiscoverUsesConnectionAccountForOrg(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()
	a := NewAzureDevOps("id", "sec", "") // no configured org → fall back to connection.Account
	a.APIBase = srv.URL
	if _, err := a.Discover(context.Background(), platform.Connection{ID: "c1", Account: "stored-org"}, "tok"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, "/stored-org/_apis/git/repositories") {
		t.Errorf("org should come from connection.Account, hit %q", path)
	}
}

func TestAzureDevOps_WatchPushHook(t *testing.T) {
	a := NewAzureDevOps("i", "s", "acme")
	trigs, err := a.Watch(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"},
		[]byte(`{"eventType":"git.push","resource":{"repository":{"remoteUrl":"https://dev.azure.com/acme/Core/_git/api","name":"api","project":{"name":"Core"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(trigs) != 1 || trigs[0].Kind != platform.TriggerPush || trigs[0].AssetTarget != "https://dev.azure.com/acme/Core/_git/api" {
		t.Errorf("trigger wrong: %+v", trigs)
	}
	// a non-push event is a no-op
	if n, _ := a.Watch(context.Background(), platform.Connection{}, []byte(`{"eventType":"git.pullrequest.created"}`)); len(n) != 0 {
		t.Errorf("non-push event should be no-op, got %+v", n)
	}
}

func TestAzureDevOps_ExchangeToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAllConn(r)
		if !strings.Contains(body, "grant_type=urn") || !strings.Contains(body, "client_assertion=sec") {
			t.Errorf("token request body wrong: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"abc123","token_type":"jwt-bearer"}`))
	}))
	defer srv.Close()
	a := NewAzureDevOps("id", "sec", "acme")
	a.OAuthBase = srv.URL
	conn, err := a.Exchange(context.Background(), "code", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if conn.Kind != platform.ConnAzureDevOps || conn.SecretRef != "abc123" || conn.Account != "acme" {
		t.Errorf("connection wrong: %+v", conn)
	}
}

func TestAzureDevOps_OAuthURLAndKind(t *testing.T) {
	a := NewAzureDevOps("cid", "sec", "acme")
	if a.Kind() != platform.ConnAzureDevOps {
		t.Errorf("kind = %q", a.Kind())
	}
	u := a.OAuthURL("st", "https://app/cb")
	for _, want := range []string{"client_id=cid", "state=st", "oauth2/authorize", "response_type=Assertion"} {
		if !strings.Contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestAzureDevOps_ApplyOpensPR(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	a := NewAzureDevOps("i", "s", "acme")
	a.APIBase = srv.URL
	act := platform.Action{Kind: platform.ActOpenPR, Title: "fix", Payload: map[string]any{
		"project": "Core", "repo_id": "r1", "head": "tsengine/fix", "base": "main",
	}}
	if err := a.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotPath, "/acme/Core/_apis/git/repositories/r1/pullrequests") {
		t.Errorf("apply should POST a PR to the repo, hit %q", gotPath)
	}
}

// readAllConn drains a request body to a string (local helper for the form-encoded token test).
func readAllConn(r *http.Request) (string, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return string(buf), nil
		}
	}
}
