package identitylinks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/estateingest"
)

// One fake server plays GitHub (REST + GraphQL) and Okta, in the providers' documented shapes.
// The tests then run the REAL join (estateingest.GitHubIdentity) over what was fetched, because
// the point of this package is that the chain becomes drawable.
func fakeProviders(t *testing.T, saml, okta bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "no token", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/orgs/acme/members" && r.URL.Query().Get("role") == "admin":
			w.Write([]byte(`[{"login":"ada-acme","id":1001}]`))
		case r.URL.Path == "/orgs/acme/members" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", `<http://`+r.Host+`/orgs/acme/members?per_page=100&page=2>; rel="next"`)
			w.Write([]byte(`[{"login":"ada-acme","id":1001},{"login":"bobbuilds","id":1002}]`))
		case r.URL.Path == "/orgs/acme/members":
			w.Write([]byte(`[{"login":"contractor-x","id":1003}]`))
		case r.URL.Path == "/repos/acme/shop/collaborators":
			w.Write([]byte(`[{"login":"bobbuilds","permissions":{"admin":false,"push":true}},{"login":"contractor-x","permissions":{"admin":true,"push":true}},{"login":"reader","permissions":{"admin":false,"push":false}}]`))
		case r.URL.Path == "/repos/acme/private/collaborators":
			http.Error(w, `{"message":"Must have push access"}`, 403)
		case r.URL.Path == "/graphql":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "externalIdentities") {
				http.Error(w, "unexpected query", 400)
				return
			}
			if !saml {
				w.Write([]byte(`{"data":{"organization":{"samlIdentityProvider":null}}}`))
				return
			}
			w.Write([]byte(`{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"pageInfo":{"hasNextPage":false,"endCursor":null},
			  "nodes":[{"user":{"login":"ada-acme"},"samlIdentity":{"nameId":"Ada@acme.io"}},{"user":null,"samlIdentity":{"nameId":"pending@acme.io"}}]}}}}}`))
		case r.URL.Path == "/api/v1/apps":
			w.Write([]byte(`[{"id":"app-gh","name":"github_enterprise_cloud_org","label":"GitHub","status":"ACTIVE"},{"id":"app-slack","name":"slack","label":"Slack","status":"ACTIVE"}]`))
		case r.URL.Path == "/api/v1/apps/app-gh/users":
			if !okta {
				w.Write([]byte(`[]`))
				return
			}
			w.Write([]byte(`[{"id":"00u1","externalId":"1002","credentials":{"userName":"bob@acme.io"},"profile":{"email":"Bob@acme.io"}},
			                 {"id":"00u2","externalId":"","credentials":{"userName":"new@acme.io"},"profile":{}},
			                 {"id":"00u3","externalId":"9999","credentials":{"userName":"ghost@acme.io"},"profile":{"email":"ghost@acme.io"}}]`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestFetch_JoinsSAMLAndOktaToGitHubAuthorityAndNamesWhatItCouldNotRead(t *testing.T) {
	srv := fakeProviders(t, true, true)
	defer srv.Close()
	opts := Options{GitHubAPIBase: srv.URL, OktaOrgURL: srv.URL, HTTP: srv.Client()}
	set := Fetch(context.Background(), opts, Inputs{TenantID: "t1", GitHubOrg: "acme", GitHubToken: "gh", OktaToken: "ok",
		Repos: []string{"acme/shop", "acme/private"}, Now: time.Now()})

	links := map[string]string{}
	for _, l := range set.Links {
		links[l.Login] = l.Email + "|" + l.Source
	}
	if links["ada-acme"] != "ada@acme.io|"+SourceGitHubSAML {
		t.Errorf("SAML link missing or wrong: %v", links)
	}
	if links["bobbuilds"] != "bob@acme.io|"+SourceOktaSCIM {
		t.Errorf("Okta SCIM link (joined on GitHub id 1002) missing or wrong: %v", links)
	}
	if _, has := links["contractor-x"]; has {
		t.Error("contractor-x is asserted by nobody and must not be linked")
	}
	for _, l := range set.Links {
		if l.Email == "ghost@acme.io" || l.Email == "pending@acme.io" || l.Email == "new@acme.io" {
			t.Errorf("an assignment with no matching GitHub member, a pending invite, or no provisioned id became a link: %+v", l)
		}
	}

	var org, repoPush, repoAdmin int
	for _, c := range set.Controls {
		switch {
		case c.Repo == "" && c.Admin && c.Login == "ada-acme":
			org++
		case c.Repo == "shop" && c.Login == "bobbuilds" && !c.Admin:
			repoPush++
		case c.Repo == "shop" && c.Login == "contractor-x" && c.Admin:
			repoAdmin++
		case c.Login == "reader":
			t.Error("a read-only collaborator holds no authority and must not be a control")
		}
		if len(c.Evidence) == 0 {
			t.Errorf("control without evidence: %+v", c)
		}
	}
	if org != 1 || repoPush != 1 || repoAdmin != 1 {
		t.Errorf("controls: org=%d push=%d admin=%d of %+v", org, repoPush, repoAdmin, set.Controls)
	}
	if !strings.Contains(set.Unread["collaborators:acme/private"], "403") {
		t.Errorf("the refused repository must be NAMED as unread: %v", set.Unread)
	}

	// The real join now draws the chain for the linked people and names the unlinked one.
	res := estateingest.GitHubIdentity(set.Links, set.Controls, time.Now())
	if res.Linked < 2 {
		t.Errorf("expected at least ada (org) and bob (shop) linked, got %d", res.Linked)
	}
	if len(res.UnlinkedLogins) != 1 || res.UnlinkedLogins[0] != "contractor-x" {
		t.Errorf("contractor-x must be reported as the unlinked authority: %v", res.UnlinkedLogins)
	}
}

func TestFetch_NoSAMLAndNoProvisioningAreNamedNotSilent(t *testing.T) {
	srv := fakeProviders(t, false, false)
	defer srv.Close()
	opts := Options{GitHubAPIBase: srv.URL, OktaOrgURL: srv.URL, HTTP: srv.Client()}
	set := Fetch(context.Background(), opts, Inputs{TenantID: "t1", GitHubOrg: "acme", GitHubToken: "gh", OktaToken: "ok", Now: time.Now()})
	if len(set.Links) != 0 {
		t.Errorf("no source asserted a link, yet links were produced: %+v", set.Links)
	}
	if !strings.Contains(set.Unread[SourceGitHubSAML], "no SAML identity provider") {
		t.Errorf("an org without SAML must be named: %v", set.Unread)
	}
	if !strings.Contains(set.Unread[SourceOktaSCIM], "SCIM provisioning") {
		t.Errorf("an Okta app with no provisioned ids must be named: %v", set.Unread)
	}
	if len(set.Controls) == 0 {
		t.Error("GitHub authority is still readable without any link source")
	}
}

func TestFetch_ScopeRefusalOnSAMLIsNamedWithTheScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/graphql":
			w.Write([]byte(`{"data":{"organization":null},"errors":[{"type":"INSUFFICIENT_SCOPES","message":"Your token has not been granted the required scopes"}]}`))
		case "/orgs/acme/members":
			w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	set := Fetch(context.Background(), Options{GitHubAPIBase: srv.URL, HTTP: srv.Client()}, Inputs{TenantID: "t1", GitHubOrg: "acme", GitHubToken: "gh", Now: time.Now()})
	if !strings.Contains(set.Unread[SourceGitHubSAML], "admin:org") {
		t.Errorf("a scope refusal must tell the owner which scope: %v", set.Unread)
	}
	if set.Unread[SourceOktaSCIM] != "no Okta connection" {
		t.Errorf("no Okta must be named as such: %v", set.Unread)
	}
}

func TestFetch_NoGitHubMeansNothingIsAssertedAboutCode(t *testing.T) {
	set := Fetch(context.Background(), Options{}, Inputs{TenantID: "t1", OktaToken: "ok", Now: time.Now()})
	if len(set.Links) != 0 || len(set.Controls) != 0 || set.Unread["github"] == "" || set.Unread[SourceOktaSCIM] == "" {
		b, _ := json.Marshal(set)
		t.Errorf("without GitHub nothing can be joined and both must be named: %s", b)
	}
}
