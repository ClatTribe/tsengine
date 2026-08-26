package cloudengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A retired/unsupported model comes back as a 200 whose info.error carries the real reason and ZERO
// text parts. The client must surface that reason, not the opaque "empty response" that read as a
// capability/throttle miss in the bench autopsy (the dead-model → BRAIN-STALL mislabel).
func TestOpenCode_SurfacesEmbeddedProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/session") {
			_, _ = w.Write([]byte(`{"id":"ses_test"}`))
			return
		}
		// exact shape the live zen provider returned for a retired model
		_, _ = w.Write([]byte(`{"parts":[],"info":{"role":"assistant","error":{"name":"APIError","data":{"message":"Model x-preview-f-free is not supported","statusCode":401,"isRetryable":false}}}}`))
	}))
	defer srv.Close()

	o := &OpenCode{baseURL: srv.URL, user: "opencode", pass: "x", model: "opencode/x-preview-f-free", http: srv.Client()}
	_, err := o.Generate(context.Background(), "hi")
	if err == nil {
		t.Fatal("expected an error for an unsupported model, got nil")
	}
	if !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("error should surface the real provider message + status, got %q", err)
	}
	if strings.Contains(err.Error(), "empty response") {
		t.Fatalf("must NOT mask a real provider error as 'empty response', got %q", err)
	}
}

// A retryable provider fault must render with an "HTTP <code>" substring so llmretry classifies it
// transient (the same retry path every agent loop shares).
func TestOpenCode_RetryableProviderErrorIsTransientShaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/session") {
			_, _ = w.Write([]byte(`{"id":"ses_test"}`))
			return
		}
		_, _ = w.Write([]byte(`{"parts":[],"info":{"error":{"name":"APIError","data":{"message":"upstream overloaded","statusCode":503,"isRetryable":true}}}}`))
	}))
	defer srv.Close()

	o := &OpenCode{baseURL: srv.URL, user: "opencode", pass: "x", model: "opencode/m", http: srv.Client()}
	_, err := o.Generate(context.Background(), "hi")
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("retryable provider error should carry HTTP 503, got %q", err)
	}
}
