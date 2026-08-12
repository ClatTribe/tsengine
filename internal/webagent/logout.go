package webagent

import (
	"fmt"
	"strings"
)

// logout.go grounds the ONE session-management flaw with a clean, false-positive-free predicate:
// logout that does not invalidate the session server-side.
//
// THE GAP. tridentsecurity.io/solutions/web-app tests "logout invalidation" and "session fixation" as
// named authentication cases. We prove IDOR, privesc, injection and access-control — nothing about the
// SESSION LIFECYCLE. Logout is the tractable one: a token that still works after the user logged out is
// the account-takeover primitive behind every stolen-laptop and shared-terminal story, and it has a
// binary answer.
//
// WHY IT IS FP-FREE, AND WHY OTHER SESSION CHECKS ARE NOT. The naive test — "log out, does the cookie
// still 200" — is FP-prone: many apps 200 a logged-out request and just render the login page, so a
// status code proves nothing. This uses the SAME differential shape as bola_probe: a PRIVATE marker the
// authenticated session can read. The predicate fires ONLY when
//
//	(1) the marker is PRESENT while logged in   — proves the session really had access, and
//	(2) the marker is ABSENT after hitting logout with that same cookie — proves logout removed it.
//
// …and it flags the FAILURE as the inverse: still present after logout. A nil/short marker refuses to
// ground, exactly like the other probes. The model PROPOSES the cookie, the logout URL and the marker;
// the deterministic predicate DISPOSES. Session FIXATION is deliberately left out — proving it needs a
// pre-auth vs post-auth session-id comparison the agent cannot always observe, and a shaky predicate
// here would be worse than the honest gap.

// sessionInvalidationFailed reports whether the session SURVIVED logout: the private marker was readable
// before, the logout call was made, and the marker is STILL readable with the same cookie afterward.
//
// before = the authed read; after = the read with the same cookie AFTER calling logout. Grounded: both
// must actually contain (or not) the marker; a marker too short to be distinctive never grounds.
func sessionInvalidationFailed(before, after *Resp, marker string) bool {
	if before == nil || after == nil || len(strings.TrimSpace(marker)) < 4 {
		return false
	}
	hadIt := statusOK(before.Status) && strings.Contains(before.Body, marker)
	stillHasIt := strings.Contains(after.Body, marker)
	// The vuln is: it worked before, and it STILL works after logout.
	return hadIt && stillHasIt
}

// tLogoutProbe runs the before→logout→after sequence and sets session_invalidation_failed when the
// session outlived its own logout.
func tLogoutProbe(cc *Context, args map[string]any) string {
	protected := strings.TrimSpace(argStr(args, "protected_url"))
	logoutURL := strings.TrimSpace(argStr(args, "logout_url"))
	cookie := strings.TrimSpace(argStr(args, "session_cookie"))
	marker := strings.TrimSpace(argStr(args, "marker"))
	if protected == "" || logoutURL == "" || cookie == "" || marker == "" {
		return "ERROR: logout_probe(protected_url, logout_url, session_cookie, marker) — all four required. " +
			"protected_url = an authenticated page that renders session-PRIVATE data; logout_url = the app's " +
			"logout endpoint; session_cookie = the logged-in session; marker = a private datum you can see on " +
			"protected_url while logged in (their email/account-no — NOT nav/chrome text)."
	}
	if len(marker) < 4 {
		return "ERROR: marker is too short to ground on (>=4 chars) — pick a distinctive private value."
	}
	if !cc.req.AllowedURL(protected) {
		return "ERROR: protected_url is out of scope: " + protected
	}
	if !cc.req.AllowedURL(logoutURL) {
		return "ERROR: logout_url is out of scope: " + logoutURL
	}

	// One session (one cookie jar), three ordered requests: read → logout → read again. Same Requester
	// so the logout's own Set-Cookie (if any) is honoured, exactly as a browser would.
	r := NewRequester(cc.req.AllowHosts(), 3, 0)
	h := map[string]string{"Cookie": cookie}

	before, bErr := r.Send(cc.ctx, "GET", protected, "", h)
	_, lErr := r.Send(cc.ctx, "GET", logoutURL, "", h)
	after, aErr := r.Send(cc.ctx, "GET", protected, "", h)
	if bErr != nil || lErr != nil || aErr != nil {
		return fmt.Sprintf("REQUEST FAILED (read=%v logout=%v reread=%v)", bErr, lErr, aErr)
	}

	failed := sessionInvalidationFailed(before, after, marker)

	cc.turnN++
	ind := []string{}
	if failed {
		ind = append(ind, "session_invalidation_failed")
	}
	cc.History = append(cc.History, Turn{
		ID:         fmt.Sprintf("t-%03d", cc.turnN),
		Method:     "GET",
		URL:        protected,
		Status:     after.Status,
		Indicators: ind,
		RespSnippet: fmt.Sprintf("logout differential: before=%d after=%d marker=%q present[before=%t after=%t]",
			before.Status, after.Status, marker,
			strings.Contains(before.Body, marker), strings.Contains(after.Body, marker)),
	})

	if failed {
		return fmt.Sprintf("SESSION INVALIDATION FAILED (turn t-%03d cited): the private marker was readable "+
			"BEFORE logout and STILL readable with the same cookie AFTER logout — the server did not "+
			"invalidate the session. This is the account-takeover primitive: a stolen token stays valid "+
			"past logout. Cite this turn in record_finding(class=broken_session_management).", cc.turnN)
	}
	return fmt.Sprintf("NOT CONFIRMED: marker present before logout = %t, after = %t. Grounds ONLY when it was "+
		"present before AND still present after (the session outlived its logout). If it was absent before, "+
		"the marker is not session-private — pick a better one.",
		strings.Contains(before.Body, marker), strings.Contains(after.Body, marker))
}
