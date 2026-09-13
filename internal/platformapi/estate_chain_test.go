package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// THE CHAIN, END TO END THROUGH THE STORE. A stored link set (the pass's fetch) and a snapshot that
// kept the OIDC trusts (the ingest's derivation) must compose into person → repository → cloud role,
// and the estate response must say who could not be linked and why.
func TestEstate_DrawsPersonToRepoToRoleFromStoredInputs(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	now := time.Now().UTC()
	_ = st.PutIdentityLinks(ctx, platform.IdentityLinkSet{TenantID: "t1", FetchedAt: now,
		Links: []platform.IdentityLink{{Email: "bob@acme.io", Login: "bob", Source: "github_saml"}},
		Controls: []platform.GitHubControl{
			{Login: "bob", Org: "acme", Repo: "shop", Admin: false, Evidence: []string{"GET /repos/acme/shop/collaborators"}},
			{Login: "contractor-x", Org: "acme", Repo: "shop", Admin: true, Evidence: []string{"GET /repos/acme/shop/collaborators"}},
		},
		Unread: map[string]string{"okta_scim": "no Okta connection"}})
	snaps := cloudsnap.NewMemStore()
	_ = snaps.Put(ctx, cloudsnap.Snapshot{TenantID: "t1", Inventory: []byte(`{"provider":"aws","account_id":"123456789012","resources":[]}`), CapturedAt: now,
		GitHubTrusts: []cloudsnap.GitHubTrust{{Repository: "acme/shop", RoleARN: "arn:aws:iam::123456789012:role/deploy", RoleName: "deploy",
			Privileged: true, Evidence: []string{"trust-policy:arn:aws:iam::123456789012:role/deploy"}}}})
	d := Deps{Store: st, CloudSnapshots: snaps}

	g, err := d.composeEstate(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	person := estategraph.Canonical("identity", "bob@acme.io")
	repo := estategraph.Canonical("code", "acme/shop")
	role := estategraph.Canonical("cloud", "arn:aws:iam::123456789012:role/deploy")
	var owns, assumes bool
	for _, e := range g.Edges {
		if e.From == person && e.To == repo && e.Kind == estategraph.EdgeOwns {
			owns = true
		}
		if e.From == repo && e.To == role && e.Kind == estategraph.EdgeAssumes {
			assumes = true
		}
	}
	if !owns {
		t.Error("the person → repository edge was not drawn from the stored link set")
	}
	if !assumes {
		t.Error("the repository → role edge was not drawn from the snapshot's stored trusts")
	}

	rec := httptest.NewRecorder()
	d.handleEstateGraph(rec, httptest.NewRequest(http.MethodGet, "/v1/estate", nil), "t1")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		IdentityLinks *struct {
			Linked         int               `json:"linked"`
			UnlinkedLogins []string          `json:"unlinked_logins"`
			ChainBroken    string            `json:"chain_broken"`
			Unread         map[string]string `json:"unread"`
		} `json:"identity_links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.IdentityLinks == nil {
		t.Fatal("the response carries no identity_links account of the join")
	}
	if out.IdentityLinks.Linked != 1 || len(out.IdentityLinks.UnlinkedLogins) != 1 || out.IdentityLinks.UnlinkedLogins[0] != "contractor-x" {
		t.Errorf("join account: %+v", out.IdentityLinks)
	}
	if !strings.Contains(out.IdentityLinks.ChainBroken, "SCIM") || out.IdentityLinks.Unread["okta_scim"] == "" {
		t.Errorf("the broken chain must name the integration that mends it and what was unread: %+v", out.IdentityLinks)
	}

	// No link set at all is a different fact from an empty one: null, not zeros.
	st2 := store.NewMemory()
	_ = st2.PutTenant(ctx, platform.Tenant{ID: "t2"})
	rec2 := httptest.NewRecorder()
	Deps{Store: st2}.handleEstateGraph(rec2, httptest.NewRequest(http.MethodGet, "/v1/estate", nil), "t2")
	if !strings.Contains(rec2.Body.String(), `"identity_links":null`) {
		t.Errorf("with no link set the response must say null, got %s", rec2.Body.String())
	}
}

// The trusts are derived at ingest on BOTH doors and kept on the snapshot. Through the live sync,
// with the same any-repo-trusting role the CI-identity test uses plus a pinned one.
func TestCloudSync_StoresTheOIDCTrustsOnTheSnapshot(t *testing.T) {
	d := syncDeps(t, fetchLister{out: []awsfetch.Bucket{{Name: "logs"}}}, true)
	pinned := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/shop:*"}}}]}`
	d.AWSFetcher = func(c platform.Connection) awsfetch.Fetcher {
		return awsfetch.Fetcher{AccountID: c.Account, Buckets: fetchLister{out: []awsfetch.Bucket{{Name: "logs"}}},
			Principals: fetchIAM{out: []awsfetch.Principal{
				{ARN: "arn:aws:iam::123456789012:role/deploy", Name: "deploy", Role: true, Admin: true, Trust: pinned},
				{ARN: "arn:aws:iam::123456789012:role/open", Name: "open", Role: true, Trust: anyRepoTrust},
			}}}
	}
	if _, _, err := d.SyncCloudInventory(context.Background(), "ten-1"); err != nil {
		t.Fatal(err)
	}
	snap, ok, _ := d.CloudSnapshots.Get(context.Background(), "ten-1")
	if !ok || len(snap.GitHubTrusts) != 1 {
		t.Fatalf("exactly the pinned repository trust must be stored (a wildcard names no repository): %+v", snap.GitHubTrusts)
	}
	if tr := snap.GitHubTrusts[0]; tr.Repository != "acme/shop" || !strings.HasSuffix(tr.RoleARN, "role/deploy") || !tr.Privileged {
		t.Errorf("trust: %+v", tr)
	}
	g, err := Deps{Store: d.Store, CloudSnapshots: d.CloudSnapshots}.composeEstate(context.Background(), "ten-1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.Kind == estategraph.EdgeAssumes && e.From == estategraph.Canonical("code", "acme/shop") {
			found = true
		}
	}
	if !found {
		t.Error("the estate composed after a live sync does not carry the repository → role edge")
	}
}
