package osint

import (
	"context"
	"testing"
)

func TestParseCT_DedupsAndScopes(t *testing.T) {
	// a realistic crt.sh response: dupes, a wildcard, a newline-joined SAN list, and an out-of-scope SAN.
	body := []byte(`[
	  {"name_value":"app.acme.com","common_name":"app.acme.com"},
	  {"name_value":"app.acme.com"},
	  {"name_value":"*.acme.com","common_name":"acme.com"},
	  {"name_value":"legacy.acme.com\nvpn.acme.com","common_name":"legacy.acme.com"},
	  {"name_value":"notacme.evil.com","common_name":"notacme.evil.com"}
	]`)
	hosts := ParseCT("acme.com", body)
	got := map[string]bool{}
	for _, h := range hosts {
		got[h.Host] = true
		if h.Source != "crtsh" {
			t.Errorf("source should be crtsh, got %q", h.Source)
		}
	}
	for _, want := range []string{"acme.com", "app.acme.com", "legacy.acme.com", "vpn.acme.com"} {
		if !got[want] {
			t.Errorf("expected %s from CT", want)
		}
	}
	if got["notacme.evil.com"] {
		t.Error("out-of-scope SAN must be dropped (grounding)")
	}
	if got["*.acme.com"] {
		t.Error("a wildcard must not appear as a literal host")
	}
	if len(hosts) != 4 { // acme.com, app, legacy, vpn — deduped
		t.Errorf("want 4 deduped hosts, got %d: %+v", len(hosts), hosts)
	}
}

func TestCollectCT_MarksKnownInScopeAndBestEffort(t *testing.T) {
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if url == CTQueryURL("acme.com") {
			return []byte(`[{"name_value":"app.acme.com"},{"name_value":"legacy.acme.com"}]`), nil
		}
		return nil, context.DeadlineExceeded // a failing domain must not abort the whole collection
	}
	snap := CollectCT(context.Background(), "acme", []string{"acme.com", "broken.com"},
		map[string]bool{"app.acme.com": true}, fetch)
	if len(snap.ExposedHosts) != 2 {
		t.Fatalf("want 2 hosts (broken.com fetch failed, swallowed), got %d", len(snap.ExposedHosts))
	}
	var appInScope, legacyShadow bool
	for _, h := range snap.ExposedHosts {
		if h.Host == "app.acme.com" && h.InScope {
			appInScope = true
		}
		if h.Host == "legacy.acme.com" && !h.InScope {
			legacyShadow = true
		}
	}
	if !appInScope {
		t.Error("a host already in the monitored inventory should be marked InScope (not shadow exposure)")
	}
	if !legacyShadow {
		t.Error("an unmonitored CT host should stay shadow exposure (InScope=false)")
	}
}
