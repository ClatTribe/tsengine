package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestBitbucket_DiscoverReposToAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		// One page, next:"" so the bounded loop terminates.
		_, _ = w.Write([]byte(`{"values":[
			{"full_name":"acme/web","is_private":true,"links":{"html":{"href":"https://bitbucket.org/acme/web"}}},
			{"full_name":"acme/site","is_private":false,"links":{"html":{"href":"https://bitbucket.org/acme/site"}}}
		],"next":""}`))
	}))
	defer srv.Close()

	b := NewBitbucket("id", "sec")
	b.APIBase = srv.URL
	assets, err := b.Discover(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("want 2 assets, got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "repository" || a.Target != "https://bitbucket.org/acme/web" || a.ConnectionID != "c1" {
		t.Errorf("asset wrong: %+v", a)
	}
	if a.Meta["path"] != "acme/web" || a.Meta["visibility"] != "private" {
		t.Errorf("asset meta wrong: %+v", a.Meta)
	}
	if assets[1].Meta["visibility"] != "public" {
		t.Errorf("second repo should be public: %+v", assets[1].Meta)
	}
}

func TestBitbucket_DiscoverFollowsPagination(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.RawQuery, "page=2") {
			// page 1 → points at page 2 (absolute URL back to this server)
			_, _ = w.Write([]byte(`{"values":[{"full_name":"acme/one","links":{"html":{"href":"https://bitbucket.org/acme/one"}}}],"next":"` + "http://" + r.Host + `/repositories?page=2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"values":[{"full_name":"acme/two","links":{"html":{"href":"https://bitbucket.org/acme/two"}}}],"next":""}`))
	}))
	defer srv.Close()
	b := NewBitbucket("id", "sec")
	b.APIBase = srv.URL
	assets, err := b.Discover(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if hits != 2 || len(assets) != 2 {
		t.Fatalf("want 2 pages + 2 assets, got hits=%d assets=%d", hits, len(assets))
	}
}

func TestBitbucket_WatchPushHook(t *testing.T) {
	b := NewBitbucket("a", "b")
	trigs, err := b.Watch(context.Background(), platform.Connection{ID: "c1", TenantID: "t1"},
		[]byte(`{"push":{"changes":[]},"repository":{"full_name":"acme/web","links":{"html":{"href":"https://bitbucket.org/acme/web"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(trigs) != 1 || trigs[0].Kind != platform.TriggerPush || trigs[0].AssetTarget != "https://bitbucket.org/acme/web" {
		t.Errorf("trigger wrong: %+v", trigs)
	}
	// a non-push payload (no "push" key) is a no-op
	if n, _ := b.Watch(context.Background(), platform.Connection{}, []byte(`{"repository":{"full_name":"acme/web"}}`)); len(n) != 0 {
		t.Errorf("non-push hook should be no-op, got %+v", n)
	}
}

func TestBitbucket_ExchangeToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "cid" || p != "sec" {
			t.Errorf("token request must use Basic auth (consumer key/secret), got u=%q ok=%v", u, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"abc123","token_type":"bearer"}`))
	}))
	defer srv.Close()
	b := NewBitbucket("cid", "sec")
	b.OAuthBase = srv.URL
	conn, err := b.Exchange(context.Background(), "code", "https://app/cb")
	if err != nil {
		t.Fatal(err)
	}
	if conn.Kind != platform.ConnBitbucket || conn.SecretRef != "abc123" || conn.Status != platform.ConnActive {
		t.Errorf("connection wrong: %+v", conn)
	}
}

func TestBitbucket_OAuthURLAndKind(t *testing.T) {
	b := NewBitbucket("cid", "sec")
	if b.Kind() != platform.ConnBitbucket {
		t.Errorf("kind = %q", b.Kind())
	}
	u := b.OAuthURL("st", "https://app/cb")
	for _, want := range []string{"client_id=cid", "state=st", "site/oauth2/authorize", "response_type=code"} {
		if !contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestBitbucket_ApplyOpensPR(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	b := NewBitbucket("a", "b")
	b.APIBase = srv.URL
	act := platform.Action{Kind: platform.ActOpenPR, Title: "fix", Payload: map[string]any{"path": "acme/web", "head": "tsengine/fix", "base": "main"}}
	if err := b.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatal(err)
	}
	if gotPath == "" || !contains(gotPath, "pullrequests") || !contains(gotPath, "acme/web") {
		t.Errorf("apply should POST a pull request to the repo, hit %q", gotPath)
	}
}
