package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestSafeChain_BlocksMaliciousInManifest(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	body := `{"packages":[
	  {"ecosystem":"npm","name":"react","version":"18.2.0"},
	  {"ecosystem":"npm","name":"ua-parser-js","version":"0.7.29"}
	]}`
	rec := do(h, "POST", "/v1/safechain/check", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"safe":false`) || !strings.Contains(out, `"blocked":1`) {
		t.Errorf("a manifest with a malicious package must be unsafe with blocked:1, got %s", out)
	}
	if !strings.Contains(out, `"allowed":false`) {
		t.Error("the malicious package's verdict must be allowed:false")
	}
}

func TestSafeChain_AllowsCleanManifest(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "POST", "/v1/safechain/check", "t1", `{"packages":[{"ecosystem":"npm","name":"react","version":"18.2.0"}]}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"safe":true`) {
		t.Fatalf("a clean manifest must be safe, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSafeChain_EmptyIs400(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	if rec := do(h, "POST", "/v1/safechain/check", "t1", `{"packages":[]}`); rec.Code != 400 {
		t.Errorf("empty manifest should 400, got %d", rec.Code)
	}
}
