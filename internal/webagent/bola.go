package webagent

import (
	"fmt"
	"strings"
)

// BOLA / IDOR grounding — the false-positive-free two-session differential (the apiauthz.Evaluate
// model, §10). Broken Object-Level Authorization is business logic, so no OSS scanner grounds it; the
// honest signal is a DIFFERENTIAL: a victim-private datum that the victim's own session reads, a
// DISTINCT attacker session ALSO reads, and an unauthenticated request does NOT. A one-session "I got
// different data on another id" heuristic is FP-prone (public per-object endpoints, the attacker's OWN
// object), which is exactly why this class needed a real victim-baseline feature rather than a loose
// indicator. The three legs are each necessary; a missing leg is never assumed.

// bolaConfirmed is the deterministic predicate. marker is a VICTIM-PRIVATE token (an email, account
// number, SSN — a value that belongs to the victim, taken from the victim's own baseline response).
func bolaConfirmed(victim, attacker, unauth *Resp, marker string) bool {
	marker = strings.TrimSpace(marker)
	// A too-short marker is collision-prone (it could coincidentally appear anywhere) — refuse to ground.
	if len(marker) < 4 || victim == nil || attacker == nil {
		return false
	}
	// Leg 1 — OWNERSHIP baseline: the victim's OWN session reads the object (2xx) and it carries the
	// private marker. This proves the object is really the victim's (not an invented target).
	if !statusOK(victim.Status) || !strings.Contains(victim.Body, marker) {
		return false
	}
	// Leg 2 — VIOLATION: a DISTINCT attacker session reads the SAME victim-private marker with a
	// success status (the attacker sees data it does not own).
	if !statusOK(attacker.Status) || !strings.Contains(attacker.Body, marker) {
		return false
	}
	// Leg 3 — ACCESS-CONTROLLED, not public: an unauthenticated request must NOT reveal the marker.
	// A nil control means we could not run it → refuse to ground (never assume access control). This
	// leg also auto-rejects a badly-chosen public marker: if it's public it shows up here too.
	if unauth == nil || strings.Contains(unauth.Body, marker) {
		return false
	}
	return true
}

func statusOK(s int) bool { return s >= 200 && s < 300 }

// tBolaProbe runs the three-session differential and, when it holds, records a turn carrying the
// `bola_confirmed` indicator so record_finding(class=idor|bola) can ground on it. The LLM PROPOSES the
// two session cookies (from two accounts it registered) + the victim-private marker; the deterministic
// predicate DISPOSES — so the model can never upgrade a finding by itself (no LLM false positives).
func tBolaProbe(cc *Context, args map[string]any) string {
	url := argStr(args, "url")
	aCookie := strings.TrimSpace(argStr(args, "attacker_cookie"))
	vCookie := strings.TrimSpace(argStr(args, "victim_cookie"))
	marker := strings.TrimSpace(argStr(args, "marker"))
	if url == "" || aCookie == "" || vCookie == "" || marker == "" {
		return "ERROR: bola_probe(url, attacker_cookie, victim_cookie, marker) — all four are required. " +
			"url = the VICTIM's object (e.g. /account?id=<victim>); the two cookies are DISTINCT sessions " +
			"from two accounts you registered; marker = a victim-PRIVATE datum you saw in the victim's own response."
	}
	if aCookie == vCookie {
		return "ERROR: attacker_cookie and victim_cookie are identical — they must be TWO DISTINCT sessions " +
			"(register a second account) for the cross-principal differential to mean anything."
	}
	if !cc.req.AllowedURL(url) {
		return "ERROR: url is out of scope: " + url
	}
	// THREE fresh, isolated Requesters (same scope) so the victim/attacker/unauth cookie jars never
	// cross-contaminate — each fires exactly one GET.
	hosts := cc.req.AllowHosts()
	send := func(cookie string) (*Resp, error) {
		r := NewRequester(hosts, 2, 0)
		var h map[string]string
		if cookie != "" {
			h = map[string]string{"Cookie": cookie}
		}
		return r.Send(cc.ctx, "GET", url, "", h)
	}
	vResp, vErr := send(vCookie)
	aResp, aErr := send(aCookie)
	uResp, uErr := send("") // unauthenticated control
	if vErr != nil || aErr != nil || uErr != nil {
		return fmt.Sprintf("REQUEST FAILED (victim=%v attacker=%v unauth=%v)", vErr, aErr, uErr)
	}

	confirmed := bolaConfirmed(vResp, aResp, uResp, marker)

	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "bola_confirmed")
	}
	t := Turn{
		ID:         fmt.Sprintf("t-%03d", cc.turnN),
		Method:     "GET",
		URL:        url,
		Status:     aResp.Status,
		Indicators: ind,
		RespSnippet: fmt.Sprintf("bola differential: victim=%d attacker=%d unauth=%d marker=%q present[v=%t a=%t u=%t]",
			vResp.Status, aResp.Status, uResp.Status, marker,
			strings.Contains(vResp.Body, marker), strings.Contains(aResp.Body, marker), strings.Contains(uResp.Body, marker)),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: bola_confirmed NOT set — the differential did not hold.\n"+
			"  victim(own)  status=%d marker_present=%t   (need 2xx + marker: the object is the victim's)\n"+
			"  attacker     status=%d marker_present=%t   (need 2xx + marker: attacker reads victim's data)\n"+
			"  unauth       status=%d marker_present=%t   (need marker ABSENT: proves access-controlled, not public)\n"+
			"Fix the leg that failed (e.g. pick a marker that is genuinely victim-private and appears verbatim in the victim's response), then re-probe.",
			t.ID, vResp.Status, strings.Contains(vResp.Body, marker),
			aResp.Status, strings.Contains(aResp.Body, marker),
			uResp.Status, strings.Contains(uResp.Body, marker))
	}
	return fmt.Sprintf("%s: bola_confirmed — the attacker session read the victim-private marker %q that an "+
		"unauthenticated request could NOT (victim=%d attacker=%d unauth=%d). A DISTINCT principal read data it "+
		"does not own = broken object-level authorization. Cite %s in record_finding(class=idor).",
		t.ID, marker, vResp.Status, aResp.Status, uResp.Status, t.ID)
}
