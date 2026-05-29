package amass

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestParse_ScopeAndDedup(t *testing.T) {
	blob := []byte("api.example.com\nwww.example.com\napi.example.com\nevil.com\n  \nexample.com\n")
	findings, surface := parse(blob, "example.com")
	// api, www, example (apex); dup api dropped; evil.com out of scope; blank skipped.
	if len(surface) != 3 {
		t.Fatalf("surface = %v, want 3 in-scope hosts", surface)
	}
	if len(findings) != len(surface) {
		t.Errorf("findings(%d) should mirror surface(%d)", len(findings), len(surface))
	}
	for _, h := range surface {
		if h == "evil.com" {
			t.Error("out-of-scope host leaked")
		}
	}
}

func TestParse_Empty(t *testing.T) {
	f, s := parse(nil, "x.com")
	if f != nil || s != nil {
		t.Error("nil expected")
	}
}

func TestAmass_Identity(t *testing.T) {
	a := New()
	if a.Name() != "amass" || !a.SandboxExecution() {
		t.Error("identity wrong")
	}
	if _, ok := tool.Get("amass"); !ok {
		t.Error("amass not registered")
	}
}
