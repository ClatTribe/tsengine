package ownership

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver struct {
	recs []string
	err  error
}

func (f fakeResolver) LookupTXT(_ context.Context, _ string) ([]string, error) { return f.recs, f.err }

func TestVerify_DNSMethod(t *testing.T) {
	ch := NewChallenge("acme.com", "tok1")
	r := fakeResolver{recs: []string{"tsengine-site-verification=tok1"}}
	res := Verify(context.Background(), ch, r, nil)
	if !res.Verified || res.Method != "dns" {
		t.Fatalf("want dns-verified, got %+v", res)
	}
}

func TestVerify_FileMethodFallback(t *testing.T) {
	ch := NewChallenge("acme.com", "tok1")
	r := fakeResolver{recs: []string{"v=spf1 -all"}} // no token in DNS
	fetch := func(_ context.Context, _ string) (string, error) { return "tsengine-site-verification=tok1", nil }
	res := Verify(context.Background(), ch, r, fetch)
	if !res.Verified || res.Method != "file" {
		t.Fatalf("want file-verified, got %+v", res)
	}
}

// Grounded §10: neither method carries the token (or both error) → unverified, never assumed.
func TestVerify_Unverified(t *testing.T) {
	ch := NewChallenge("acme.com", "tok1")
	r := fakeResolver{err: errors.New("nxdomain")}
	fetch := func(_ context.Context, _ string) (string, error) { return "nothing", nil }
	if res := Verify(context.Background(), ch, r, fetch); res.Verified {
		t.Fatalf("absent token must not verify, got %+v", res)
	}
}

func TestHost(t *testing.T) {
	cases := map[string]string{
		"https://app.acme.com/path":   "app.acme.com",
		"https://app.acme.com:8443/x": "app.acme.com",
		"http://acme.com":             "acme.com",
		"acme.com":                    "acme.com",
		"acme.com:8080":               "acme.com",
		"1.2.3.4":                     "1.2.3.4",
		"1.2.3.4:443":                 "1.2.3.4",
	}
	for in, want := range cases {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewChallenge(t *testing.T) {
	c := NewChallenge("https://app.acme.com", "abc123")
	if c.Host != "app.acme.com" {
		t.Errorf("host: %q", c.Host)
	}
	if c.DNSName != "_tsengine.app.acme.com" {
		t.Errorf("dns name: %q", c.DNSName)
	}
	if c.DNSValue != "tsengine-site-verification=abc123" {
		t.Errorf("dns value: %q", c.DNSValue)
	}
	if c.FileURL != "https://app.acme.com/.well-known/tsengine-verification.txt" {
		t.Errorf("file url: %q", c.FileURL)
	}
}

// Verified only when the token is actually present — the proof, not an attestation (grounded §10).
func TestVerifyTXT(t *testing.T) {
	tok := "abc123"
	if !VerifyTXT([]string{"v=spf1 -all", "tsengine-site-verification=abc123"}, tok) {
		t.Error("prefixed token in a record should verify")
	}
	if !VerifyTXT([]string{"abc123"}, tok) {
		t.Error("bare token should verify (customer pasted just the value)")
	}
	if VerifyTXT([]string{"v=spf1 -all", "other-stuff"}, tok) {
		t.Error("absent token must NOT verify")
	}
	if VerifyTXT(nil, tok) {
		t.Error("no records must NOT verify")
	}
	if VerifyTXT([]string{"tsengine-site-verification=abc123"}, "") {
		t.Error("empty token must never verify")
	}
	// a DIFFERENT tenant's token must not cross-verify
	if VerifyTXT([]string{"tsengine-site-verification=abc123"}, "zzz999") {
		t.Error("a different token must not verify")
	}
}

func TestVerifyFile(t *testing.T) {
	if !VerifyFile("tsengine-site-verification=abc123\n", "abc123") {
		t.Error("file with the token should verify")
	}
	if VerifyFile("nothing here", "abc123") {
		t.Error("file without the token must not verify")
	}
}
