package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The pass reads Okta's configuration through the onboarded token, assesses it, stores the findings
// and reports the surface as observed; with no org URL, no connection, or a token that reads
// nothing, the surface was NOT observed.
func TestSyncOktaPosture_ReadsPoliciesThroughTheConnectionAndStores(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer okta-tok" {
			http.Error(w, "no token", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "OKTA_SIGN_ON":
			w.Write([]byte(`[{"id":"p1","name":"Default","status":"ACTIVE"}]`))
		case r.URL.Path == "/api/v1/policies/p1/rules":
			w.Write([]byte(`[{"name":"All","status":"ACTIVE","actions":{"signon":{"access":"ALLOW","requireFactor":false}}}]`))
		default:
			http.Error(w, "nope", 403)
		}
	}))
	defer srv.Close()

	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive, Account: "acme", SecretRef: "sealed"})
	n := 0
	svc := &Service{Store: st, Tokens: idTokens{tok: "okta-tok"}, NewID: func() string { n++; return itoa(n) }, OktaOrgURL: srv.URL, OktaHTTP: srv.Client()}

	out, ran := svc.syncOktaPosture(ctx, "t1")
	if !ran {
		t.Fatal("policies were read → ran must be true")
	}
	if len(out) != 1 || out[0].RuleID != "sspm::okta::sign-on-rule-without-mfa" || out[0].ID == "" {
		t.Fatalf("exactly the factor-less sign-on rule should fire, with an id: %+v", out)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != 1 {
		t.Errorf("the finding must be persisted: %d", len(stored))
	}

	// No org URL configured → not observed, and no network call attempted.
	svc.OktaOrgURL = ""
	if _, ran := svc.syncOktaPosture(ctx, "t1"); ran {
		t.Error("without OKTA_ORG_URL the org cannot be read and must not count as observed")
	}
	// A token that reads nothing → not observed (the fetcher refuses an empty org).
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 403) }))
	defer dead.Close()
	svc.OktaOrgURL, svc.OktaHTTP = dead.URL, dead.Client()
	if _, ran := svc.syncOktaPosture(ctx, "t1"); ran {
		t.Error("a token that reaches no endpoint must not count as an observed, clean org")
	}
}
