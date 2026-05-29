package crtsh

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestUniqueHosts_ScopeDedupWildcard(t *testing.T) {
	entries := []crtEntry{
		{NameValue: "*.example.com\napi.example.com", CommonName: "www.example.com"},
		{NameValue: "api.example.com"},      // dup
		{NameValue: "evil.com"},             // out of scope
		{NameValue: "deep.sub.example.com"}, // in scope (suffix)
		{CommonName: "example.com"},         // apex itself
	}
	got := uniqueHosts(entries, "example.com")
	want := map[string]bool{
		"example.com": true, "www.example.com": true,
		"api.example.com": true, "deep.sub.example.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d unique in-scope hosts", got, len(want))
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host %q (out-of-scope or wildcard leaked?)", h)
		}
	}
	// Sorted (deterministic).
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("not sorted: %v", got)
		}
	}
}

func TestCrtSh_Identity(t *testing.T) {
	c := New()
	if c.Name() != "crtsh" || !c.SandboxExecution() {
		t.Error("identity wrong")
	}
	if _, ok := tool.Get("crtsh"); !ok {
		t.Error("crtsh not registered")
	}
}
