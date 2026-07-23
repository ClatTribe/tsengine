package webagent

import (
	"fmt"
	"strings"
)

// CORS misconfiguration — the FP-free grounding for a dangerous cross-origin resource-sharing policy: a
// server that REFLECTS an arbitrary request Origin into Access-Control-Allow-Origin together with
// Access-Control-Allow-Credentials:true. That combination lets a malicious cross-origin site issue
// credentialed requests and READ the responses — session-scoped data theft from any logged-in victim.
// It was a class the offensive agent could observe but had no way to RECORD. Same house pattern as
// bola/nosqli/tamper: the LLM PROPOSES the probe (a URL + optionally an attacker origin); a deterministic
// predicate DISPOSES over the real response headers.
//
// FP discipline (§10): grounds ONLY on a REFLECTED arbitrary origin (or the special "null" origin) WITH
// credentials. ACAO:"*" is deliberately NOT grounded — browsers forbid the wildcard together with
// credentials, so a "*" policy is not credential-exploitable and must never false-positive. A static
// ACAO pinned to one trusted origin also never grounds (it won't equal our arbitrary canary origin).

// corsConfirmed reports the dangerous, credential-exfiltrating CORS misconfiguration: the response
// echoes the arbitrary attackerOrigin we sent (or "null") in Access-Control-Allow-Origin AND allows
// credentials. Reflecting an origin the caller CHOSE proves the server trusts any origin (not a fixed
// allowlist), which is the exploitable condition.
func corsConfirmed(resp *Resp, attackerOrigin string) bool {
	if resp == nil || !resp.ACAC { // credentials must be allowed, else a cross-origin reader gets no session data
		return false
	}
	acao := strings.TrimSpace(resp.ACAO)
	if acao == "" || acao == "*" { // "*" + credentials is browser-forbidden → not exploitable, never ground
		return false
	}
	return strings.EqualFold(acao, strings.TrimSpace(attackerOrigin)) || strings.EqualFold(acao, "null")
}

// tCORSProbe sends a request carrying an attacker-controlled Origin and grounds cors_confirmed on the
// reflected-origin + credentials differential.
func tCORSProbe(cc *Context, args map[string]any) string {
	rawURL := strings.TrimSpace(argStr(args, "url"))
	if rawURL == "" {
		return "ERROR: cors_probe(url [, origin, cookie]) — url required. Sends a request with an attacker-controlled " +
			"Origin header and checks whether the response reflects it (or 'null') in Access-Control-Allow-Origin WITH " +
			"Access-Control-Allow-Credentials:true — the FP-free dangerous CORS misconfig (a cross-origin attacker can read " +
			"this app's credentialed responses). Provide the app's own session cookie so the response is credentialed."
	}
	if !cc.req.AllowedURL(rawURL) {
		return "OUT OF SCOPE: " + rawURL + " is not in the authorized target allowlist."
	}
	origin := strings.TrimSpace(argStr(args, "origin"))
	if origin == "" {
		origin = "https://tsengine-cors-canary.attacker.example"
	}
	cookie := argStr(args, "cookie")
	hdr := map[string]string{"Origin": origin}
	if cookie != "" {
		hdr["Cookie"] = cookie
	}
	resp, err := cc.req.Send(cc.ctx, "GET", rawURL, "", hdr)
	if err != nil {
		return "REQUEST FAILED: " + err.Error()
	}
	confirmed := corsConfirmed(resp, origin)

	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "cors_confirmed")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: "GET", URL: rawURL, Status: resp.Status, Indicators: ind,
		RespSnippet: fmt.Sprintf("cors probe: sent Origin=%q → Access-Control-Allow-Origin=%q Access-Control-Allow-Credentials=%t", origin, resp.ACAO, resp.ACAC),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: cors_confirmed NOT set. Sent Origin=%q → ACAO=%q, ACAC=%t. "+
			"Grounds ONLY when the response reflects your arbitrary Origin (or 'null') AND Access-Control-Allow-Credentials is true. "+
			"An ACAO of '*' is not exploitable with credentials (browser-forbidden), and a static trusted origin won't reflect yours — neither grounds.",
			t.ID, origin, resp.ACAO, resp.ACAC)
	}
	return fmt.Sprintf("%s: cors_confirmed — the server reflected the attacker Origin %q into Access-Control-Allow-Origin with "+
		"Access-Control-Allow-Credentials:true, so a malicious cross-origin site can read this app's credentialed responses "+
		"(cross-origin session-data theft). Cite %s in record_finding(class=cors).", t.ID, origin, t.ID)
}
