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

func notifyDeps(t *testing.T) (Deps, store.Store) {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st, Vault: vault}, st
}

func putNotify(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/v1/settings/notifications", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handlePutNotifySettings(rec, req, "ten-1")
	return rec
}

func TestNotifySettings_SealRedactResolve(t *testing.T) {
	d, st := notifyDeps(t)
	const hook = "https://hooks.slack.com/services/T000/B000/XXXXsecretXXXX"

	rec := putNotify(d, `{"slack_webhook":"`+hook+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), hook) {
		t.Error("PUT response must not echo the webhook URL")
	}
	if !strings.Contains(rec.Body.String(), `"has_slack_webhook":true`) {
		t.Errorf("PUT should report has_slack_webhook:true, got %s", rec.Body.String())
	}

	// Stored ref must be SEALED, not the plaintext URL.
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if !tn.HasSlackWebhook() || strings.Contains(tn.SlackWebhookRef, hook) {
		t.Errorf("webhook must be stored sealed, got ref %q", tn.SlackWebhookRef)
	}
	// Redacted() must strip it (so GET /v1/tenant never leaks it).
	if tn.Redacted().SlackWebhookRef != "" {
		t.Error("Redacted() must strip the sealed webhook ref")
	}
	// The resolver opens it back to the original URL.
	if url, ok := d.ResolveTenantSlackWebhook(context.Background(), "ten-1"); !ok || url != hook {
		t.Errorf("resolver should return the original URL, got %q ok=%v", url, ok)
	}
}

func TestNotifySettings_EmptyClears(t *testing.T) {
	d, _ := notifyDeps(t)
	putNotify(d, `{"slack_webhook":"https://hooks.slack.com/services/A/B/C"}`)
	rec := putNotify(d, `{"slack_webhook":""}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_slack_webhook":false`) {
		t.Errorf("clearing should report has_slack_webhook:false, got %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := d.ResolveTenantSlackWebhook(context.Background(), "ten-1"); ok {
		t.Error("after clearing, the resolver must report no webhook")
	}
}

func TestNotifySettings_RejectsNonSlackURL(t *testing.T) {
	d, _ := notifyDeps(t)
	rec := putNotify(d, `{"slack_webhook":"https://evil.example.com/hook"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a non-Slack URL must be 400, got %d", rec.Code)
	}
}

func TestNotifySettings_NoVaultRefuses(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"})
	d := Deps{Store: st} // no Vault
	rec := putNotify(d, `{"slack_webhook":"https://hooks.slack.com/services/A/B/C"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("without a vault, sealing a webhook must fail (500), got %d", rec.Code)
	}
}

func TestNotifySettings_GetReportsPresence(t *testing.T) {
	d, _ := notifyDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/settings/notifications", nil)
	rec := httptest.NewRecorder()
	d.handleGetNotifySettings(rec, req, "ten-1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_slack_webhook":false`) {
		t.Errorf("GET on a fresh tenant should report false, got %d %s", rec.Code, rec.Body.String())
	}
}
