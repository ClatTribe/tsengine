package webagent

import "testing"

// TestResolveRequestBody covers the silent-empty-body bug: send_request's help documents an OBJECT
// body (body={"field":"val"}), but argStr returned "" for a non-string, so the documented body was
// dropped and the request went out EMPTY — breaking every JSON-API POST (request.json() → opaque 500)
// and every HTML <form> POST (request.form → 400 BadRequestKeyError). resolveRequestBody must now
// serialize it: JSON by default, form-urlencoded when the agent set a form Content-Type.
func TestResolveRequestBody(t *testing.T) {
	// 1. string body — used verbatim (the agent hand-built the wire form)
	if got := resolveRequestBody(map[string]any{"body": "ip_address=127.0.0.1"}, nil); got != "ip_address=127.0.0.1" {
		t.Errorf("string body must be verbatim, got %q", got)
	}

	// 2. object body, no Content-Type → JSON (the documented default; was silently "" before)
	if got := resolveRequestBody(map[string]any{"body": map[string]any{"job_type": "admin"}}, nil); got != `{"job_type":"admin"}` {
		t.Errorf("object body must JSON-marshal, got %q", got)
	}

	// 3. object body + a form Content-Type → application/x-www-form-urlencoded (the HTML <form> POST)
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if got := resolveRequestBody(map[string]any{"body": map[string]any{"ip_address": "127.0.0.1; id"}}, h); got != "ip_address=127.0.0.1%3B+id" {
		t.Errorf("object + form CT must url-encode, got %q", got)
	}

	// 4. nil / absent body → empty (a GET, or a bodyless POST)
	if got := resolveRequestBody(map[string]any{}, nil); got != "" {
		t.Errorf("absent body must be empty, got %q", got)
	}

	// 5. the header match is case-insensitive and tolerates charset suffixes
	h2 := map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
	if got := resolveRequestBody(map[string]any{"body": map[string]any{"a": "b"}}, h2); got != "a=b" {
		t.Errorf("case-insensitive/charset form CT must url-encode, got %q", got)
	}
}

// TestFormEncode_Deterministic: url.Values.Encode sorts by key, so multi-field form bodies are stable
// (a signed evidence bundle / transcript must reproduce byte-for-byte).
func TestFormEncode_Deterministic(t *testing.T) {
	m := map[string]any{"b": "2", "a": "1", "c": "3"}
	if got := formEncode(m); got != "a=1&b=2&c=3" {
		t.Errorf("formEncode not sorted/deterministic, got %q", got)
	}
	// non-string values are stringified (a JSON number/bool the object may carry)
	if got := formEncode(map[string]any{"n": 42, "ok": true}); got != "n=42&ok=true" {
		t.Errorf("formEncode non-string values, got %q", got)
	}
}
