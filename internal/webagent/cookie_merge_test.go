package webagent

import (
	"net/http"
	"testing"
)

// TestMergeCookieHeader covers the token-forgery override: an explicit Cookie header must WIN over the
// jar's persisted login cookie per-name (else every base64-id / JWT forgery IDOR chain dead-ends),
// while jar cookies the agent did NOT override are preserved.
func TestMergeCookieHeader(t *testing.T) {
	jar := []*http.Cookie{{Name: "access_token", Value: "Bearer MQ=="}, {Name: "sid", Value: "x"}}

	// explicit forge of access_token wins; sid preserved; no duplicate access_token
	if got := mergeCookieHeader(jar, "access_token=Bearer Mg=="); got != "access_token=Bearer Mg==; sid=x" {
		t.Errorf("forge override = %q", got)
	}
	// jar-only (no explicit) => normal authed request
	if got := mergeCookieHeader(jar, ""); got != "access_token=Bearer MQ==; sid=x" {
		t.Errorf("jar-only = %q", got)
	}
	// no cookies at all => empty (no Cookie header sent)
	if got := mergeCookieHeader(nil, ""); got != "" {
		t.Errorf("empty = %q", got)
	}
	// explicit cookie the jar doesn't have => added alongside jar cookies
	if got := mergeCookieHeader(jar, "csrf=abc"); got != "csrf=abc; access_token=Bearer MQ==; sid=x" {
		t.Errorf("explicit extra = %q", got)
	}
	// a forged value containing '=' and a space is kept VERBATIM (not re-split/mangled)
	if got := mergeCookieHeader(nil, "t=a.b=c d"); got != "t=a.b=c d" {
		t.Errorf("verbatim value = %q", got)
	}
}
