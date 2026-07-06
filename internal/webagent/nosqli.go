package webagent

import (
	"fmt"
	"strings"
)

// NoSQL (MongoDB) injection — the FP-free grounding for the classic operator-injection auth/filter
// bypass (a login or search where a client string reaches a Mongo query and an operator payload like
// {"$ne":null} / username[$ne]= / {"$regex":".*"} bypasses it). The agent could EXPLOIT this (XBEN-100
// GraphQL→Mongo) but had no class to RECORD it. Same house pattern as tamper/bola: the LLM PROPOSES a
// benign (control) request and an operator-injection request + the marker; a deterministic predicate
// DISPOSES. The distinguishing, FP-killing leg vs a generic value-flip: the injection payload must
// carry a MongoDB operator, so only a Mongo-flavored payload flipping access grounds it.

// mongoOperators are the tokens that mark a payload as a MongoDB-query injection (not a plain value).
var mongoOperators = []string{
	"$ne", "$gt", "$gte", "$lt", "$lte", "$regex", "$where", "$in", "$nin",
	"$exists", "$or", "$and", "$not", "$eq", "$expr", "$nor", "$type", "$mod",
}

// hasMongoOperator reports whether s carries a MongoDB query operator in either a JSON body
// ({"$ne":null}) or a bracketed query-string form (username[$ne]=).
func hasMongoOperator(s string) bool {
	for _, op := range mongoOperators {
		// match the operator as a JSON key ("$ne") or a query-string key ([$ne])
		if strings.Contains(s, "\""+op+"\"") || strings.Contains(s, "["+op+"]") || strings.Contains(s, op+":") {
			return true
		}
	}
	return false
}

// nosqliConfirmed grounds the NoSQL-injection differential: a server-originated marker is ABSENT from
// the benign (control) response, PRESENT in the operator-injection response, was NOT sent by the
// attacker (echo guard), and the injection payload actually carries a MongoDB operator (the leg that
// makes this specifically NoSQL and not a generic parameter flip).
func nosqliConfirmed(control, inject *Resp, marker, sent, injectPayload string) bool {
	marker = strings.TrimSpace(marker)
	if len(marker) < 4 || control == nil || inject == nil {
		return false
	}
	if strings.Contains(sent, marker) { // echo guard: marker is a reflection, not server content
		return false
	}
	if !hasMongoOperator(injectPayload) { // must be a Mongo-operator payload, else it's not NoSQLi
		return false
	}
	return !strings.Contains(control.Body, marker) && strings.Contains(inject.Body, marker)
}

// tNoSQLiProbe sends a control request (benign value) and an injection request that adds a MongoDB
// operator, and sets `nosqli_confirmed` when the operator payload exposes a marker the control didn't.
func tNoSQLiProbe(cc *Context, args map[string]any) string {
	method := strings.ToUpper(argStr(args, "method"))
	if method == "" {
		method = "POST"
	}
	controlURL := argStr(args, "url")
	if controlURL == "" {
		controlURL = argStr(args, "control_url")
	}
	injectURL := argStr(args, "inject_url")
	if injectURL == "" {
		injectURL = controlURL
	}
	marker := strings.TrimSpace(argStr(args, "marker"))
	controlBody := argStr(args, "control_body")
	injectBody := argStr(args, "inject_body")
	cookie := argStr(args, "cookie")
	if controlURL == "" || marker == "" {
		return "ERROR: nosqli_probe(method, url, marker [, control_body, inject_body, inject_url, cookie]) — " +
			"url + marker required. Send a CONTROL request (benign value — wrong creds / a normal search) and an " +
			"INJECTION request that adds a MongoDB operator ({\"$ne\":null}, {\"$regex\":\".*\"}, or the query-string " +
			"form username[$ne]=). Put the injection in inject_body (POST) or inject_url (query-string). marker = the " +
			"SERVER-ORIGINATED content the bypass exposes (a post-login page, a victim record, a flag) — NOT a value you send."
	}
	if !cc.req.AllowedURL(controlURL) || !cc.req.AllowedURL(injectURL) {
		return "ERROR: a probe URL is out of scope."
	}
	hdr := func() map[string]string {
		h := map[string]string{}
		if method != "GET" && method != "HEAD" {
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
	control, e1 := cc.req.Send(cc.ctx, method, controlURL, controlBody, hdr())
	inject, e2 := cc.req.Send(cc.ctx, method, injectURL, injectBody, hdr())
	if e1 != nil || e2 != nil {
		return fmt.Sprintf("REQUEST FAILED (control=%v inject=%v)", e1, e2)
	}

	injectPayload := injectURL + " " + injectBody
	sent := strings.Join([]string{controlURL, injectURL, controlBody, injectBody, cookie}, " ")
	confirmed := nosqliConfirmed(control, inject, marker, sent, injectPayload)

	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "nosqli_confirmed")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: method, URL: injectURL, Status: inject.Status, Indicators: ind,
		RespSnippet: fmt.Sprintf("nosqli differential: marker=%q control[status=%d present=%t] inject[status=%d present=%t] mongo_op=%t echo=%t",
			marker, control.Status, strings.Contains(control.Body, marker), inject.Status, strings.Contains(inject.Body, marker),
			hasMongoOperator(injectPayload), strings.Contains(sent, marker)),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: nosqli_confirmed NOT set.\n"+
			"  control marker_present=%t   (need ABSENT: the benign value yields no privileged content)\n"+
			"  inject  marker_present=%t   (need PRESENT: the operator payload exposes it)\n"+
			"  mongo_op=%t   (must be true: the injection must carry a MongoDB operator like $ne/$regex/$gt)\n"+
			"  echo=%t   (must be false: the marker must be SERVER content, not a value you sent)\n"+
			"Provide a benign control request and an injection that adds a Mongo operator, differing only in that payload.",
			t.ID, strings.Contains(control.Body, marker), strings.Contains(inject.Body, marker),
			hasMongoOperator(injectPayload), strings.Contains(sent, marker))
	}
	return fmt.Sprintf("%s: nosqli_confirmed — a MongoDB operator payload exposed the server-originated marker %q "+
		"(absent with the benign value, and not sent by you). NoSQL (MongoDB) injection. "+
		"Cite %s in record_finding(class=nosqli).", t.ID, marker, t.ID)
}
