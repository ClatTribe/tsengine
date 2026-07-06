package webagent

import (
	"fmt"
	"strings"
)

// Self-privilege-escalation / mass-assignment grounding — the FP-free SUBSET of broken function-level
// authorization (§10). General BFLA ("a low-priv user called an admin-only function") needs a policy
// fact — "this function is privileged" — that responses alone can't prove, so it stays apiauthz's job
// (operator-declared TestConfig). But a user promoting THEMSELVES is unambiguously a vuln regardless of
// policy, and it grounds on an OBSERVED state transition of the session's OWN privilege: absent in the
// baseline read, present after the call that granted it. The before/after differential on the SAME page
// auto-excludes a marker that was static all along (nav chrome), so no policy declaration is needed.
// This is OWASP API #3 (BFLA) + #6 (mass-assignment) — a top real-VAPT finding class.

// privescConfirmed is the deterministic predicate. roleAfter is a HIGH-privilege marker (e.g.
// `role=admin`, `"is_admin":true`) the session should NOT have.
func privescConfirmed(before, after *Resp, roleAfter string) bool {
	roleAfter = strings.TrimSpace(roleAfter)
	if len(roleAfter) < 3 || before == nil || after == nil {
		return false
	}
	// Baseline: the session's own privilege read succeeds and does NOT yet show the high-priv marker
	// (grounds the low-privilege starting state; also excludes a marker that is static on the page).
	if !statusOK(before.Status) || strings.Contains(before.Body, roleAfter) {
		return false
	}
	// After the escalation call, the SAME session's read now shows the high-priv marker — an observed
	// transition caused by the only action taken between the two reads.
	if !statusOK(after.Status) || !strings.Contains(after.Body, roleAfter) {
		return false
	}
	return true
}

// tPrivescProbe runs the before → escalate → after sequence on ONE session and sets `privesc_confirmed`
// when the session escalated its own privilege. The LLM PROPOSES the session cookie, the escalation
// request, the verify URL, and the high-priv marker (all per-target inputs, so the engine stays
// general — no app-specific logic baked in); the deterministic predicate DISPOSES, so the model can
// never upgrade a finding itself (no LLM false positives).
func tPrivescProbe(cc *Context, args map[string]any) string {
	cookie := strings.TrimSpace(argStr(args, "session_cookie"))
	verifyURL := argStr(args, "verify_url")
	roleAfter := strings.TrimSpace(argStr(args, "role_after"))
	esc, _ := args["escalate"].(map[string]any)
	if cookie == "" || verifyURL == "" || roleAfter == "" || esc == nil {
		return "ERROR: privesc_probe(session_cookie, verify_url, role_after, escalate{method,url,body}) — all required. " +
			"session_cookie = a NORMAL user's session; verify_url = where that user's own role/privilege is reflected " +
			"(e.g. /me, /profile); role_after = a HIGH-privilege marker you should NOT have (e.g. role=admin); " +
			"escalate = the request that tries to grant it (e.g. POST /profile body={\"role\":\"admin\"})."
	}
	escURL := argStr(esc, "url")
	if escURL == "" {
		return "ERROR: escalate.url is required (the privilege-granting request's URL)."
	}
	if !cc.req.AllowedURL(verifyURL) || !cc.req.AllowedURL(escURL) {
		return "ERROR: verify_url or escalate.url is out of scope."
	}
	escMethod := strings.ToUpper(argStr(esc, "method"))
	if escMethod == "" {
		escMethod = "POST"
	}
	escHeaders := argStrMap(esc, "headers")
	escBody := resolveRequestBody(esc, escHeaders)
	if looksJSONBody(escBody) && !hasHeaderFold(escHeaders, "content-type") {
		if escHeaders == nil {
			escHeaders = map[string]string{}
		}
		escHeaders["Content-Type"] = "application/json"
	}

	// ONE fresh Requester so the whole sequence is the SAME session (the cookie is re-sent on every
	// request); scope inherited. The explicit Cookie header seeds it (empty jar → just the explicit).
	r := NewRequester(cc.req.AllowHosts(), 6, 0)
	ch := map[string]string{"Cookie": cookie}
	before, e1 := r.Send(cc.ctx, "GET", verifyURL, "", ch)
	// escalate: carry the session cookie plus the escalate step's own headers
	eh := map[string]string{"Cookie": cookie}
	for k, v := range escHeaders {
		eh[k] = v
	}
	_, e2 := r.Send(cc.ctx, escMethod, escURL, escBody, eh)
	after, e3 := r.Send(cc.ctx, "GET", verifyURL, "", ch)
	if e1 != nil || e2 != nil || e3 != nil {
		return fmt.Sprintf("REQUEST FAILED (before=%v escalate=%v after=%v)", e1, e2, e3)
	}

	confirmed := privescConfirmed(before, after, roleAfter)
	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "privesc_confirmed")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: escMethod, URL: escURL, Status: after.Status, Indicators: ind,
		RespSnippet: fmt.Sprintf("privesc differential: marker=%q before[status=%d present=%t] after[status=%d present=%t]",
			roleAfter, before.Status, strings.Contains(before.Body, roleAfter), after.Status, strings.Contains(after.Body, roleAfter)),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: privesc_confirmed NOT set — no privilege transition.\n"+
			"  before  status=%d marker_present=%t   (need 2xx + marker ABSENT: you start low-privilege)\n"+
			"  after   status=%d marker_present=%t   (need 2xx + marker PRESENT: the call granted it)\n"+
			"If both reads show the marker it was static (not a transition); if neither, the escalation didn't take — "+
			"check the escalate request shape (field name, content-type) and the marker string.",
			t.ID, before.Status, strings.Contains(before.Body, roleAfter),
			after.Status, strings.Contains(after.Body, roleAfter))
	}
	return fmt.Sprintf("%s: privesc_confirmed — the session's own privilege marker %q was ABSENT before your "+
		"escalate call and PRESENT after (before=%d after=%d). A user granting itself privilege = self-privilege-"+
		"escalation / mass-assignment. Cite %s in record_finding(class=mass_assignment) or class=privilege_escalation.",
		t.ID, roleAfter, before.Status, after.Status, t.ID)
}
