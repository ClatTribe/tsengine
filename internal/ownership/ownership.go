// Package ownership is the proof-of-asset-ownership challenge — the control security leaders named as a
// precondition for trusting AI-driven testing ("proof of asset ownership", State-of-AI-in-Pentesting p35).
// For a standalone target a customer ADDS (a domain / web app / IP they typed, vs a system they connected
// via OAuth, which already proves control), this requires them to publish a per-asset token via DNS or a
// well-known file before the engine will treat the asset as owner-verified.
//
// This package is the PURE half: it builds the challenge instructions and verifies a token is actually
// present in a DNS TXT record or a fetched file. The live DNS resolution + SSRF-screened HTTP fetch are the
// caller's job (the gated half), so verification is grounded (§10) — owner-verified only when the token is
// really found, never asserted.
package ownership

import (
	"context"
	"net/url"
	"strings"
)

// Prefix namespaces the published value so it can't collide with the customer's other DNS/file content.
const Prefix = "tsengine-site-verification="

// WellKnownPath is where the file-method token is published (relative to the target's https root).
const WellKnownPath = "/.well-known/tsengine-verification.txt"

// DNSLabel is prepended to the host for the TXT-record method (a dedicated record, not the apex).
const DNSLabel = "_tsengine"

// Challenge is the set of instructions a customer follows to prove they control a target. They satisfy
// EITHER method (DNS or file) — both carry the same token.
type Challenge struct {
	Token       string `json:"token"`        // the random per-asset secret to publish
	Host        string `json:"host"`         // the bare hostname the methods target
	DNSName     string `json:"dns_name"`     // TXT record name: _tsengine.<host>
	DNSValue    string `json:"dns_value"`    // the TXT value to set: Prefix + token
	FileURL     string `json:"file_url"`     // https://<host>/.well-known/tsengine-verification.txt
	FileContent string `json:"file_content"` // the file body to serve: Prefix + token
}

// NewChallenge builds the instructions for a target + its stored token.
func NewChallenge(target, token string) Challenge {
	h := Host(target)
	val := Prefix + token
	return Challenge{
		Token:       token,
		Host:        h,
		DNSName:     DNSLabel + "." + h,
		DNSValue:    val,
		FileURL:     "https://" + h + WellKnownPath,
		FileContent: val,
	}
}

// Host extracts the bare hostname from a target (strips scheme, path, port). "https://app.acme.com:8443/x"
// → "app.acme.com"; "acme.com" → "acme.com"; "1.2.3.4" → "1.2.3.4".
func Host(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	// no scheme: cut path, then port
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, ":"); i >= 0 && !strings.Contains(t, "]") {
		// strip a trailing :port (but leave bare IPv6 in brackets alone)
		if _, after, ok := strings.Cut(t[i:], ":"); ok && isPort(after) {
			t = t[:i]
		}
	}
	return strings.Trim(t, "[]")
}

func isPort(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// VerifyTXT reports whether any of the DNS TXT records carries the token (accepting the value with or
// without the prefix, so a customer who pastes just the token still verifies). Grounded: a match requires
// the token to actually be present — an empty/missing record never verifies.
func VerifyTXT(records []string, token string) bool {
	return contains(records, token)
}

// VerifyFile reports whether a fetched file body carries the token.
func VerifyFile(body, token string) bool {
	return contains([]string{body}, token)
}

func contains(haystacks []string, token string) bool {
	if token == "" {
		return false
	}
	want := Prefix + token
	for _, h := range haystacks {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if strings.Contains(h, want) || strings.Contains(h, token) {
			return true
		}
	}
	return false
}

// Resolver is the DNS surface the verifier needs — satisfied by *net.Resolver (mirrors operate.Resolver).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Fetch returns a URL's body. The caller injects an SSRF-screened, bounded HTTP client (so the file
// method can't be turned into a server-side request forgery — the same guard /v1/assess uses).
type Fetch func(ctx context.Context, url string) (string, error)

// Result is the grounded outcome of a live ownership check.
type Result struct {
	Verified bool   `json:"verified"`
	Method   string `json:"method,omitempty"` // "dns" | "file" | "" (unverified)
}

// Verify runs both methods against the live target — DNS TXT first, then the well-known file — and returns
// verified+method on the first that carries the token. Grounded (§10): owner-verified ONLY when the token
// is really found; a lookup error or absent token returns unverified, never assumed. Either injected
// surface may be nil (e.g. file-only) — a nil one is simply skipped.
func Verify(ctx context.Context, ch Challenge, r Resolver, fetch Fetch) Result {
	if r != nil {
		if recs, err := r.LookupTXT(ctx, ch.DNSName); err == nil && VerifyTXT(recs, ch.Token) {
			return Result{Verified: true, Method: "dns"}
		}
	}
	if fetch != nil {
		if body, err := fetch(ctx, ch.FileURL); err == nil && VerifyFile(body, ch.Token) {
			return Result{Verified: true, Method: "file"}
		}
	}
	return Result{}
}
