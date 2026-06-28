package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func jiraDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st, Vault: vault}
}

func putJira(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/v1/settings/jira", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handlePutJiraSettings(rec, req, "ten-1")
	return rec
}

func TestJiraSettings_SealRedactResolve(t *testing.T) {
	d := jiraDeps(t)
	const token = "jira-api-tok-XYZ"
	rec := putJira(d, `{"base_url":"https://acme.atlassian.net","email":"sec@acme.io","project":"SEC","api_token":"`+token+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), token) {
		t.Error("PUT response must not echo the API token")
	}
	if !strings.Contains(rec.Body.String(), `"has_token":true`) {
		t.Errorf("PUT should report has_token:true, got %s", rec.Body.String())
	}

	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if !tn.Jira.HasToken() || strings.Contains(tn.Jira.TokenRef, token) {
		t.Errorf("token must be stored sealed, got ref %q", tn.Jira.TokenRef)
	}
	if tn.Redacted().Jira != nil {
		t.Error("Redacted() must drop the Jira block (and its sealed token)")
	}
	base, email, tok, project, ok := d.ResolveTenantJira(context.Background(), "ten-1")
	if !ok || base != "https://acme.atlassian.net" || email != "sec@acme.io" || tok != token || project != "SEC" {
		t.Errorf("resolver returned wrong values: %q %q %q %q ok=%v", base, email, tok, project, ok)
	}
}

func TestJiraSettings_Validation(t *testing.T) {
	d := jiraDeps(t)
	cases := map[string]string{
		"non-https base":     `{"base_url":"http://acme.atlassian.net","email":"a@b.c","project":"SEC","api_token":"t"}`,
		"missing email":      `{"base_url":"https://acme.atlassian.net","project":"SEC","api_token":"t"}`,
		"missing project":    `{"base_url":"https://acme.atlassian.net","email":"a@b.c","api_token":"t"}`,
		"no token first time": `{"base_url":"https://acme.atlassian.net","email":"a@b.c","project":"SEC"}`,
		// SSRF: a tenant must NOT point the server-side Jira filer at an internal/metadata host.
		"ssrf metadata ip": `{"base_url":"https://169.254.169.254","email":"a@b.c","project":"SEC","api_token":"t"}`,
		"ssrf localhost":   `{"base_url":"https://localhost:8090","email":"a@b.c","project":"SEC","api_token":"t"}`,
		"ssrf private ip":  `{"base_url":"https://10.0.0.5","email":"a@b.c","project":"SEC","api_token":"t"}`,
		"ssrf reserved":    `{"base_url":"https://jira.internal","email":"a@b.c","project":"SEC","api_token":"t"}`,
	}
	for name, body := range cases {
		if rec := putJira(d, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s should be 400, got %d", name, rec.Code)
		}
	}
}

func TestJiraSettings_EmptyBaseClears(t *testing.T) {
	d := jiraDeps(t)
	putJira(d, `{"base_url":"https://acme.atlassian.net","email":"a@b.c","project":"SEC","api_token":"t"}`)
	rec := putJira(d, `{"base_url":""}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_token":false`) {
		t.Errorf("clearing should report has_token:false, got %d %s", rec.Code, rec.Body.String())
	}
	if _, _, _, _, ok := d.ResolveTenantJira(context.Background(), "ten-1"); ok {
		t.Error("after clearing, the resolver must report no Jira")
	}
}

func TestJiraSettings_NoVaultRefuses(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"})
	d := Deps{Store: st} // no Vault
	rec := putJira(d, `{"base_url":"https://acme.atlassian.net","email":"a@b.c","project":"SEC","api_token":"t"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("without a vault, sealing the token must fail (500), got %d", rec.Code)
	}
}
