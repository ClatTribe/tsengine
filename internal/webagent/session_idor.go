package webagent

import (
	"fmt"
	"strings"
)

// Session-state IDOR grounding — the FP-free proof for the class where a LOGIN request trusts a
// client-supplied field (a user_id form field, an account selector) to set SERVER session state, and
// the victim's data surfaces on a LATER authenticated GET (XBEN-043). tamper_probe grounds the
// single-request tampers (field/cookie/header, where the tamper and the marker ride the same request);
// this grounds the stateful two-step flow — tamper at login, read on a separate request — via a
// TWO-ISOLATED-SESSION differential, the same shape as bola_probe. The LLM PROPOSES the two login
// bodies + target + marker; the deterministic tamperConfirmed predicate DISPOSES.

// tSessionIDORProbe logs in twice in ISOLATED sessions (benign id vs tampered victim id), reads the
// same target in each, and sets `tamper_confirmed` when the victim marker is absent under the benign
// login and present under the tampered one (and was never sent by the attacker — the echo guard).
func tSessionIDORProbe(cc *Context, args map[string]any) string {
	loginURL := argStr(args, "login_url")
	targetURL := argStr(args, "target_url")
	baseLogin := argStr(args, "base_login_body")
	tamperLogin := argStr(args, "tamper_login_body")
	marker := strings.TrimSpace(argStr(args, "marker"))
	loginMethod := strings.ToUpper(argStr(args, "login_method"))
	if loginMethod == "" {
		loginMethod = "POST"
	}
	if loginURL == "" || targetURL == "" || baseLogin == "" || tamperLogin == "" || marker == "" {
		return "ERROR: session_idor_probe(login_url, base_login_body, tamper_login_body, target_url, marker [, login_method]) — " +
			"all required. base_login_body and tamper_login_body must differ ONLY in the tampered field (e.g. user_id=<own> vs " +
			"user_id=<victim>); target_url = the authenticated page that renders the session's user; marker = the VICTIM's " +
			"private data you expect to leak (NOT a value you send)."
	}
	if !cc.req.AllowedURL(loginURL) || !cc.req.AllowedURL(targetURL) {
		return "ERROR: login_url or target_url is out of scope."
	}
	formHdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	// One ISOLATED session per side: a fresh Requester whose jar carries the login's Set-Cookie into the
	// target GET, so the two sessions never cross-contaminate.
	run := func(loginBody string) (*Resp, error) {
		r := NewRequester(cc.req.AllowHosts(), 6, 0)
		if _, err := r.Send(cc.ctx, loginMethod, loginURL, loginBody, formHdr); err != nil {
			return nil, err
		}
		return r.Send(cc.ctx, "GET", targetURL, "", nil)
	}
	base, e1 := run(baseLogin)
	tamper, e2 := run(tamperLogin)
	if e1 != nil || e2 != nil {
		return fmt.Sprintf("REQUEST FAILED (base=%v tamper=%v)", e1, e2)
	}

	sent := strings.Join([]string{loginURL, targetURL, baseLogin, tamperLogin}, " ")
	confirmed := tamperConfirmed(base, tamper, marker, sent)

	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "tamper_confirmed")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: "GET", URL: targetURL, Status: tamper.Status, Indicators: ind,
		RespSnippet: fmt.Sprintf("session-idor differential: marker=%q base[status=%d present=%t] tamper[status=%d present=%t] echo=%t",
			marker, base.Status, strings.Contains(base.Body, marker), tamper.Status, strings.Contains(tamper.Body, marker),
			strings.Contains(sent, marker)),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: tamper_confirmed NOT set.\n"+
			"  base(own-id login)    marker_present=%t   (need ABSENT: your own session shows no victim data)\n"+
			"  tamper(victim-id login) marker_present=%t (need PRESENT: the tampered login exposes the victim)\n"+
			"  echo=%t  (must be false: the marker must be the VICTIM's server-side data, not a value you sent)\n"+
			"Ensure the two login bodies differ ONLY in the id field, target_url renders the session's user, and the marker is the victim's private data.",
			t.ID, strings.Contains(base.Body, marker), strings.Contains(tamper.Body, marker), strings.Contains(sent, marker))
	}
	return fmt.Sprintf("%s: tamper_confirmed — logging in with a tampered id exposed the victim marker %q on %s that the "+
		"attacker's own session did not (and did not send). Session-state IDOR (broken access control via a login-trusted "+
		"client field). Cite %s in record_finding(class=idor).", t.ID, marker, targetURL, t.ID)
}
