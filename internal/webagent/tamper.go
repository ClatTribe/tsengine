package webagent

import (
	"fmt"
	"strings"
)

// Broken access control via client-controlled-field tampering — the FP-free grounding for the family
// of captures where the agent flips a value the server SHOULDN'T trust (a hidden form field like
// isAdmin, a cookie/JWT claim like user_id in an unverified token) and privileged / another user's
// content appears. privesc_probe grounds the STATEFUL self-privesc transition and bola_probe the
// two-session object read; this grounds the STATELESS single-tamper case (XBEN-052 param tampering,
// XBEN-027 JWT-forge IDOR) — the agent exploited these but could record no finding. Same house pattern:
// the LLM PROPOSES the base + tampered request and the marker; a deterministic predicate DISPOSES.

// tamperConfirmed grounds the tamper differential: a SERVER-ORIGINATED privileged marker is ABSENT from
// the base response, PRESENT in the tampered response, and — the leg that kills the echo false positive
// — was NOT sent by the attacker in either request (so it can't be the tampered value reflected back).
func tamperConfirmed(base, tamper *Resp, marker, sent string) bool {
	marker = strings.TrimSpace(marker)
	if len(marker) < 4 || base == nil || tamper == nil {
		return false
	}
	// echo guard: if the attacker's own request text carries the marker, its presence in the response is
	// a reflection, not privileged server content — refuse to ground.
	if strings.Contains(sent, marker) {
		return false
	}
	return !strings.Contains(base.Body, marker) && strings.Contains(tamper.Body, marker)
}

// tTamperProbe sends a base request and a tampered request that differ ONLY in a client-controlled
// field (body field and/or cookie/token) and sets `tamper_confirmed` when the tamper exposes a
// privileged marker the base didn't (and the attacker didn't send).
func tTamperProbe(cc *Context, args map[string]any) string {
	method := strings.ToUpper(argStr(args, "method"))
	if method == "" {
		method = "GET"
	}
	baseURL := argStr(args, "base_url")
	tamperURL := argStr(args, "tamper_url")
	if tamperURL == "" {
		tamperURL = baseURL
	}
	marker := strings.TrimSpace(argStr(args, "marker"))
	if baseURL == "" || marker == "" {
		return "ERROR: tamper_probe(method, base_url, tamper_url, marker [, base_body/tamper_body, base_cookie/tamper_cookie]) — " +
			"base_url + marker required. The two requests must differ ONLY in the tampered client-controlled field " +
			"(a form field like isAdmin, or a cookie/JWT claim like user_id in an unverified token). marker = the " +
			"SERVER-ORIGINATED privileged / other-user content you expect the tamper to expose (e.g. 'Welcome Admin', a victim's email, a flag) — NOT a value you send."
	}
	baseBody := argStr(args, "base_body")
	tamperBody := argStr(args, "tamper_body")
	baseCookie := argStr(args, "base_cookie")
	tamperCookie := argStr(args, "tamper_cookie")
	if !cc.req.AllowedURL(baseURL) || !cc.req.AllowedURL(tamperURL) {
		return "ERROR: a probe URL is out of scope."
	}
	hdr := func(cookie string) map[string]string {
		h := map[string]string{}
		if method != "GET" {
			h["Content-Type"] = "application/x-www-form-urlencoded"
		}
		if cookie != "" {
			h["Cookie"] = cookie
		}
		if len(h) == 0 {
			return nil
		}
		return h
	}
	base, e1 := cc.req.Send(cc.ctx, method, baseURL, baseBody, hdr(baseCookie))
	tamper, e2 := cc.req.Send(cc.ctx, method, tamperURL, tamperBody, hdr(tamperCookie))
	if e1 != nil || e2 != nil {
		return fmt.Sprintf("REQUEST FAILED (base=%v tamper=%v)", e1, e2)
	}

	// everything the attacker SENT, for the echo guard
	sent := strings.Join([]string{baseURL, tamperURL, baseBody, tamperBody, baseCookie, tamperCookie}, " ")
	confirmed := tamperConfirmed(base, tamper, marker, sent)

	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "tamper_confirmed")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: method, URL: tamperURL, Status: tamper.Status, Indicators: ind,
		RespSnippet: fmt.Sprintf("tamper differential: marker=%q base[status=%d present=%t] tamper[status=%d present=%t] echo=%t",
			marker, base.Status, strings.Contains(base.Body, marker), tamper.Status, strings.Contains(tamper.Body, marker),
			strings.Contains(sent, marker)),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: tamper_confirmed NOT set.\n"+
			"  base   marker_present=%t   (need ABSENT: the benign value yields no privileged content)\n"+
			"  tamper marker_present=%t   (need PRESENT: the tampered value exposes it)\n"+
			"  echo=%t   (must be false: the marker must be SERVER content, not a value you sent)\n"+
			"Pick a marker that is server-originated privileged/other-user content the tamper reveals, and make the two requests differ ONLY in the tampered field.",
			t.ID, strings.Contains(base.Body, marker), strings.Contains(tamper.Body, marker), strings.Contains(sent, marker))
	}
	return fmt.Sprintf("%s: tamper_confirmed — flipping a client-controlled field exposed the server-originated marker %q "+
		"(absent in the base response, and not sent by you). Broken access control via client-trusted input. "+
		"Cite %s in record_finding(class=privilege_escalation | idor | broken_access_control).", t.ID, marker, t.ID)
}
