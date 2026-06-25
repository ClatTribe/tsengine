// Package webauth is the authenticated-web-scan depth layer (ADR 0010 Phase 3) — the gap vs
// Probely/Detectify. We already have a thin seed_auth (form-login → captured cookie); what was
// missing is RELIABILITY: modern SPA/OAuth/token logins, and — the accuracy half — KNOWING the
// session is actually valid and re-authing when it drops mid-scan. A scan that silently runs
// logged-out misses every auth-gated vulnerability (a false negative the customer never sees),
// so session validation + login-wall detection are the FN guard that makes authenticated
// coverage trustworthy.
//
// This is the deterministic, offline-testable core: the login-flow model + ValidateSession
// ("am I authenticated?") + IsLoginWall ("did my session expire?"). The live replay (running the
// steps, capturing the session) wires into the sandbox seed_auth path.
package webauth

import (
	"strconv"
	"strings"
)

// AuthType is how a session is obtained.
type AuthType string

const (
	AuthForm     AuthType = "form"     // a single login POST → captured Set-Cookie (today's seed_auth)
	AuthToken    AuthType = "token"    // a static bearer/header (SPA backends, machine clients)
	AuthRecorded AuthType = "recorded" // an ordered multi-step replay (SPA / OAuth-redirect flows)
)

// Step is one request in a login flow.
type Step struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Fields  map[string]string `json:"fields,omitempty"`  // form fields / JSON body
	Headers map[string]string `json:"headers,omitempty"` // extra headers (e.g. a CSRF token)
}

// LoginFlow is a replayable auth recipe an operator configures once per web asset.
type LoginFlow struct {
	Type  AuthType `json:"type"`
	Steps []Step   `json:"steps,omitempty"` // recorded: the ordered replay; form: the single login POST
	Token string   `json:"token,omitempty"` // token: the Authorization header value

	// ValidateURL is an authenticated-only endpoint probed to confirm the session is live.
	ValidateURL string `json:"validate_url,omitempty"`
	// SuccessMarker proves authentication (e.g. "Sign out", the user's name). When set, it is
	// the strongest signal. FailureMarker proves the opposite (e.g. "Invalid credentials").
	SuccessMarker string `json:"success_marker,omitempty"`
	FailureMarker string `json:"failure_marker,omitempty"`
}

// Valid checks a configured flow is runnable: a known type with the minimum it needs (steps with
// URLs for form/recorded, a token for token). Returns a descriptive error for the config API.
func (f LoginFlow) Valid() error {
	switch f.Type {
	case AuthToken:
		if strings.TrimSpace(f.Token) == "" {
			return errMissing("token flow requires a non-empty token")
		}
	case AuthForm, AuthRecorded:
		if len(f.Steps) == 0 {
			return errMissing("form/recorded flow requires at least one step")
		}
		for i, s := range f.Steps {
			if strings.TrimSpace(s.URL) == "" {
				return errMissing("step " + strconv.Itoa(i) + " has no url")
			}
		}
	default:
		return errMissing("type must be form, token, or recorded")
	}
	return nil
}

type validationError string

func (e validationError) Error() string { return string(e) }
func errMissing(s string) error         { return validationError("login flow: " + s) }

// Plan returns the ordered requests to obtain the session — what the live replayer executes.
// Token flows have no steps (the header is applied directly); form/recorded return their steps.
func (f LoginFlow) Plan() []Step {
	if f.Type == AuthToken {
		return nil
	}
	return f.Steps
}

// AuthHeaders is the header set to apply to every scan request for a token flow (empty otherwise
// — cookie flows carry the session in the captured cookie, not a header).
func (f LoginFlow) AuthHeaders() map[string]string {
	if f.Type == AuthToken && strings.TrimSpace(f.Token) != "" {
		return map[string]string{"Authorization": f.Token}
	}
	return nil
}

// ValidateSession decides whether a response to the ValidateURL proves we are authenticated.
// Conservative: a non-2xx is never "authenticated"; an explicit failure marker overrides a 2xx
// (a 200 login page is NOT a valid session). With a success marker, authentication requires it.
func ValidateSession(status int, body string, f LoginFlow) bool {
	if status/100 != 2 {
		return false
	}
	if m := strings.TrimSpace(f.FailureMarker); m != "" && strings.Contains(body, m) {
		return false // a 200 that still shows the login/error page → not authenticated
	}
	if m := strings.TrimSpace(f.SuccessMarker); m != "" {
		return strings.Contains(body, m)
	}
	return true // 2xx, no markers configured → best-effort authenticated
}

// loginish are substrings in a redirect Location that mean "you've been bounced to login".
var loginish = []string{"login", "signin", "sign-in", "sso", "/auth", "session", "sessionexpired", "logout", "account/login"}

// IsLoginWall reports that a response means the session is missing/expired — the signal the
// scanner uses to RE-AUTH before trusting results (the FN guard against silently scanning
// logged-out). True on 401/403, a redirect to a login-looking URL, an inline failure marker, or
// a login form served in the body (a password field).
func IsLoginWall(status int, location, body string, f LoginFlow) bool {
	if status == 401 || status == 403 {
		return true
	}
	if isRedirect(status) && looksLikeLogin(location) {
		return true
	}
	if m := strings.TrimSpace(f.FailureMarker); m != "" && strings.Contains(body, m) {
		return true
	}
	// An API / SPA auth wall: a JSON error body signalling unauthenticated (the FN gap for
	// non-HTML apps that return 200/4xx with {"error":"unauthorized"} instead of a login page).
	if looksLikeAuthErrorBody(body) {
		return true
	}
	// A login form served inline (a password input) is a strong logged-out signal.
	lb := strings.ToLower(body)
	return strings.Contains(lb, `type="password"`) || strings.Contains(lb, "type='password'")
}

// authErrorValues are the auth-failure values an API/SPA returns in a JSON error body.
var authErrorValues = []string{
	"unauthorized", "unauthenticated", "authentication required", "not authenticated",
	"login required", "token_expired", "token expired", "invalid_token", "invalid token",
	"authentication credentials were not provided", // Django REST Framework
	"jwt expired", "session expired", "missing authentication",
}

// looksLikeAuthErrorBody reports whether the body is a JSON auth-error response. FP-guarded: it
// fires ONLY when the body is JSON-ish (starts with { or [) AND carries a recognised error key
// (error/message/code/detail/title) AND an auth-failure value — so an HTML page that merely
// mentions "unauthorized" (e.g. docs about HTTP 401) does not trip it.
func looksLikeAuthErrorBody(body string) bool {
	b := strings.TrimSpace(body)
	if b == "" || (b[0] != '{' && b[0] != '[') {
		return false
	}
	lb := strings.ToLower(b)
	if !strings.Contains(lb, `"error"`) && !strings.Contains(lb, `"message"`) &&
		!strings.Contains(lb, `"code"`) && !strings.Contains(lb, `"detail"`) && !strings.Contains(lb, `"title"`) {
		return false
	}
	for _, v := range authErrorValues {
		if strings.Contains(lb, v) {
			return true
		}
	}
	return false
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func looksLikeLogin(location string) bool {
	l := strings.ToLower(location)
	for _, s := range loginish {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}
