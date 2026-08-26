// Package llmretry classifies an LLM-client error as transient (worth a backoff+retry) vs
// permanent (fail fast). It is shared by every agent loop — l2 (AI security engineer / pentest),
// cloudagent (cloud security), llmredteam, webagent (offensive web pentester) — so transient-retry
// behaviour is consistent across all the AI features, and none of them wastes attempts retrying a
// request that can never succeed.
package llmretry

import "strings"

// transientSignals are KEYWORD substrings of an LLM-client error that mean "retry might help":
// provider rate-limit / overload phrases and transient network faults. HTTP STATUS codes are NOT
// matched here — they are handled by httpStatusTransient, because every client in this tree formats
// them as "HTTP <code>" (e.g. `opencode: HTTP 503`, `anthropic: … returned HTTP 529`), NOT the
// "status <code>" spelling an earlier version of this list assumed. A substring like "status 503"
// matched NONE of the real clients, so a 5xx overload was silently classed permanent and broke the
// agent loop — the exact throttle-collapse this package exists to prevent.
var transientSignals = []string{
	"rate limit", "overloaded", "timeout", "i/o timeout", "deadline exceeded",
	"connection reset", "connection refused", "eof", "temporarily",
	// An EMPTY completion (a 200 with no text part and no embedded provider error) is a
	// nondeterministic hiccup, not a permanent fault: a model verified working on the same run
	// (short prompts, 100KB prompts) returned a single empty on turn 0 and — because the loop
	// treated it as permanent — zeroed an entire benchmark. Retrying is cheap and bounded (the
	// caller caps total retries), so an empty is worth a retry everywhere; a model that empties
	// DETERMINISTICALLY still fails, but after the cap and with a visible reason, not silently.
	"empty response",
}

// IsTransient reports whether err is a transient LLM fault worth a backoff+retry. A permanent
// fault (400/401/403/404, "no such host", invalid model) is NOT transient and must fail fast.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sig := range transientSignals {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return httpStatusTransient(s)
}

// httpStatusTransient reports whether s carries an HTTP status code — in any of the forms the LLM
// clients in this tree emit ("HTTP 503", "http/1.1 503", "status 503", "status: 503", "code 503") —
// that is a provider rate-limit (429) or a server-side overload (5xx). The code is read only when it
// immediately follows one of those prefixes, so a bare "500" elsewhere in a message (a byte count, a
// port) can never false-trip the retry.
func httpStatusTransient(s string) bool {
	for _, prefix := range []string{"http ", "http/1.1 ", "http/2 ", "status ", "status: ", "code "} {
		from := 0
		for {
			j := strings.Index(s[from:], prefix)
			if j < 0 {
				break
			}
			code := leadingInt(s[from+j+len(prefix):])
			if code == 429 || (code >= 500 && code <= 599) {
				return true
			}
			from += j + len(prefix)
		}
	}
	return false
}

// leadingInt reads the run of leading ASCII digits of s as an int (0 if none). Bounded to 4 digits
// so a long digit run can't overflow — an HTTP status is always three.
func leadingInt(s string) int {
	n, seen := 0, 0
	for i := 0; i < len(s) && seen < 4; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		seen++
	}
	if seen == 0 {
		return 0
	}
	return n
}
