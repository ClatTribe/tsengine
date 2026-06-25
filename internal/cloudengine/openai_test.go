package cloudengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAICompat_Generate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"summary\":\"ok\"}"}}]}`))
	}))
	defer srv.Close()

	t.Setenv("LLM_BASE_URL", srv.URL)
	t.Setenv("LLM_MODEL", "qwen2.5")
	c, ok := OpenAICompatFromEnv()
	if !ok {
		t.Fatal("LLM_BASE_URL set → OpenAICompatFromEnv should return ok")
	}
	if !c.local {
		t.Error("a 127.0.0.1 base URL should be detected as local (no key required)")
	}
	out, err := c.Generate(context.Background(), "summarize")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(out, "ok") {
		t.Errorf("unexpected output %q", out)
	}
}

func TestLLMFromEnv_PrefersOpenAICompatThenGemini(t *testing.T) {
	// OpenAI-compat path wins when LLM_BASE_URL is set.
	t.Setenv("LLM_BASE_URL", "http://localhost:11434/v1")
	t.Setenv("LLM_API_KEY", "")
	if _, ok := LLMFromEnv(); !ok {
		t.Fatal("LLM_BASE_URL set → LLMFromEnv should pick the OpenAI-compat client")
	}
	// Nothing set → not ok (graceful deterministic fallback).
	t.Setenv("LLM_BASE_URL", "")
	t.Setenv("LLM_PROVIDER", "")
	t.Setenv("LLM_API_KEY", "")
	if _, ok := LLMFromEnv(); ok {
		t.Error("no LLM env → LLMFromEnv should return ok=false")
	}
}
