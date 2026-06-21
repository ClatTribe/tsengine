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

func TestLLMSettings_SealRedactResolve(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-1", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st, Vault: vault}
	const apiKey = "sk-super-secret-123"

	// PUT — set provider/model + the key.
	put := httptest.NewRequest(http.MethodPut, "/v1/settings/llm", strings.NewReader(
		`{"provider":"anthropic","model":"claude-opus-4-8","api_key":"`+apiKey+`"}`))
	rec := httptest.NewRecorder()
	d.handlePutLLMSettings(rec, put, "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), apiKey) {
		t.Error("PUT response must not echo the API key")
	}
	if !strings.Contains(rec.Body.String(), `"has_key":true`) {
		t.Errorf("PUT should report has_key:true, got %s", rec.Body.String())
	}

	// Stored key must be SEALED, not plaintext.
	tn, _ := st.GetTenant(ctx, "ten-1")
	if tn.LLM == nil || tn.LLM.KeyRef == "" || strings.Contains(tn.LLM.KeyRef, apiKey) {
		t.Fatalf("stored KeyRef must be a sealed ref, got %+v", tn.LLM)
	}

	// GET — provider/model + has_key, never the key.
	rec = httptest.NewRecorder()
	d.handleGetLLMSettings(rec, httptest.NewRequest(http.MethodGet, "/v1/settings/llm", nil), "ten-1")
	body := rec.Body.String()
	if !strings.Contains(body, "anthropic") || !strings.Contains(body, "claude-opus-4-8") || !strings.Contains(body, `"has_key":true`) {
		t.Errorf("GET missing provider/model/has_key: %s", body)
	}
	if strings.Contains(body, apiKey) {
		t.Error("GET response must not contain the API key")
	}

	// ResolveTenantLLM round-trips the sealed key back to plaintext for the engine.
	prov, model, key, ok := d.ResolveTenantLLM(ctx, "ten-1")
	if !ok || prov != "anthropic" || model != "claude-opus-4-8" || key != apiKey {
		t.Errorf("resolve = (%q,%q,<key ok=%v>) want anthropic/claude-opus-4-8/%v", prov, model, ok, key == apiKey)
	}

	// The generic tenant endpoint must NEVER leak the sealed key ref (redaction).
	rec = httptest.NewRecorder()
	d.handleGetTenant(rec, httptest.NewRequest(http.MethodGet, "/v1/tenant", nil), "ten-1")
	if strings.Contains(rec.Body.String(), "key_ref") || strings.Contains(rec.Body.String(), tn.LLM.KeyRef) {
		t.Errorf("GET /v1/tenant leaked the LLM key ref: %s", rec.Body.String())
	}

	// Changing the model with an empty api_key keeps the existing key.
	rec = httptest.NewRecorder()
	d.handlePutLLMSettings(rec, httptest.NewRequest(http.MethodPut, "/v1/settings/llm",
		strings.NewReader(`{"provider":"anthropic","model":"claude-sonnet-4-6","api_key":""}`)), "ten-1")
	if _, _, key2, ok2 := d.ResolveTenantLLM(ctx, "ten-1"); !ok2 || key2 != apiKey {
		t.Error("changing the model with an empty key must preserve the existing key")
	}

	// An unknown provider is rejected.
	rec = httptest.NewRecorder()
	d.handlePutLLMSettings(rec, httptest.NewRequest(http.MethodPut, "/v1/settings/llm",
		strings.NewReader(`{"provider":"bogus","model":"x","api_key":"y"}`)), "ten-1")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown provider should be 400, got %d", rec.Code)
	}
}
