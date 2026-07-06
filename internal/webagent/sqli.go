package webagent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SQL injection grounding beyond error-based — the FP-free UNION and boolean-blind proofs the engine
// lacked (only sql_error + slow_response existed, so an agent could EXPLOIT a UNION/boolean SQLi but
// never RECORD the finding — observed on XBEN-095). Both follow the house pattern: the LLM PROPOSES
// the payloads, a deterministic predicate DISPOSES, so the model can't upgrade a finding itself (§10).

// sqlArithRe extracts a bare arithmetic sentinel A*B with multi-digit factors (the same collision-proof
// shape ssti_eval uses: a >=4-digit product is not plausibly coincidental).
var sqlArithRe = regexp.MustCompile(`(\d{2,7})\s*\*\s*(\d{2,7})`)

// sqlUnionEvaluated reports a UNION-based SQLi: the payload is a UNION SELECT carrying an arithmetic
// sentinel whose PRODUCT appears in the response while the literal expression does not — the DB
// computed it. FP-free: a mere reflection (literal echoed) or a product with no UNION context is ignored.
func sqlUnionEvaluated(payload, body string) bool {
	low := strings.ToLower(payload)
	if !strings.Contains(low, "union") || !strings.Contains(low, "select") {
		return false
	}
	m := sqlArithRe.FindStringSubmatch(payload)
	if m == nil {
		return false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	prod := a * b
	if prod < 1000 { // <4-digit products are too collision-prone to ground
		return false
	}
	ps := strconv.Itoa(prod)
	// the computed product must be present AND the literal "A*B" expression absent (computed, not echoed)
	return strings.Contains(body, ps) && !strings.Contains(body, m[0])
}

// respSimilar reports whether two responses represent the "same result": identical status and body
// length within 5%. A crude but robust proxy for the boolean differential (true≈base, false≠base).
func respSimilar(a, b *Resp) bool {
	if a == nil || b == nil || a.Status != b.Status {
		return false
	}
	la, lb := len(a.Body), len(b.Body)
	hi, lo := la, lb
	if lb > la {
		hi, lo = lb, la
	}
	if hi == 0 {
		return true
	}
	return float64(lo)/float64(hi) >= 0.95
}

// sqlBooleanConfirmed grounds boolean-blind SQLi on a differential: the TRUE condition reproduces the
// baseline result, the FALSE condition clearly does not, and true/false diverge. A reflected or ignored
// param can't produce this pattern (no false positive).
func sqlBooleanConfirmed(base, tru, fls *Resp) bool {
	if base == nil || tru == nil || fls == nil {
		return false
	}
	return respSimilar(base, tru) && !respSimilar(base, fls) && !respSimilar(tru, fls)
}

// tSqliBoolProbe runs the base/true/false differential and sets `sql_boolean` when it holds. The LLM
// PROPOSES the three request variants (it knows the injection point + a tautology/contradiction pair);
// the deterministic predicate DISPOSES. GET uses *_url; POST uses base_url + true_body/false_body.
func tSqliBoolProbe(cc *Context, args map[string]any) string {
	method := strings.ToUpper(argStr(args, "method"))
	if method == "" {
		method = "GET"
	}
	baseURL := argStr(args, "base_url")
	trueURL := argStr(args, "true_url")
	falseURL := argStr(args, "false_url")
	if baseURL == "" {
		return "ERROR: sqli_bool_probe(method, base_url, true_url, false_url [, base_body/true_body/false_body for POST]) — base_url required."
	}
	// POST variants inject via the body against a single URL; GET variants via distinct URLs.
	baseBody := argStr(args, "base_body")
	trueBody := argStr(args, "true_body")
	falseBody := argStr(args, "false_body")
	if trueURL == "" {
		trueURL = baseURL
	}
	if falseURL == "" {
		falseURL = baseURL
	}
	if !cc.req.AllowedURL(baseURL) || !cc.req.AllowedURL(trueURL) || !cc.req.AllowedURL(falseURL) {
		return "ERROR: a probe URL is out of scope."
	}
	var hdr map[string]string
	if method != "GET" {
		hdr = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	}
	base, e1 := cc.req.Send(cc.ctx, method, baseURL, baseBody, hdr)
	tru, e2 := cc.req.Send(cc.ctx, method, trueURL, trueBody, hdr)
	fls, e3 := cc.req.Send(cc.ctx, method, falseURL, falseBody, hdr)
	if e1 != nil || e2 != nil || e3 != nil {
		return fmt.Sprintf("REQUEST FAILED (base=%v true=%v false=%v)", e1, e2, e3)
	}

	confirmed := sqlBooleanConfirmed(base, tru, fls)
	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "sql_boolean")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: method, URL: trueURL, Status: tru.Status, Indicators: ind,
		RespSnippet: fmt.Sprintf("boolean-sqli differential: base[%d,%dB] true[%d,%dB] false[%d,%dB] true~base=%t false~base=%t",
			base.Status, len(base.Body), tru.Status, len(tru.Body), fls.Status, len(fls.Body),
			respSimilar(base, tru), respSimilar(base, fls)),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: sql_boolean NOT set — no boolean differential.\n"+
			"  base  status=%d len=%d\n  true  status=%d len=%d  (need ~= base: the TRUE condition reproduces the result)\n"+
			"  false status=%d len=%d  (need != base: the FALSE condition changes it)\n"+
			"If all three match, the param is ignored (not injectable); if true differs from base too, it's reflected not evaluated. "+
			"Pick a base that returns a positive result, and a tautology/contradiction pair matching the quote context.",
			t.ID, base.Status, len(base.Body), tru.Status, len(tru.Body), fls.Status, len(fls.Body))
	}
	return fmt.Sprintf("%s: sql_boolean — boolean-blind SQL injection confirmed. The TRUE condition reproduced the "+
		"baseline (status=%d) while the FALSE condition changed it (status=%d len %d→%d) — the DB evaluated the injected "+
		"boolean. Cite %s in record_finding(class=sqli).", t.ID, tru.Status, fls.Status, len(base.Body), len(fls.Body), t.ID)
}
