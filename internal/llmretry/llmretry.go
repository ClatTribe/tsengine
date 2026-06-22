// Package llmretry classifies an LLM-client error as transient (worth a backoff+retry) vs
// permanent (fail fast). It is shared by every agent loop — l2 (AI security engineer / pentest),
// cloudagent (cloud security), llmredteam — so transient-retry behaviour is consistent across all
// the AI features, and none of them wastes attempts retrying a request that can never succeed.
package llmretry

import "strings"

// transientSignals are substrings of an LLM-client error that mean "retry might help": provider
// rate-limits / overload (HTTP 429/5xx, Anthropic 529) and transient network faults.
var transientSignals = []string{
	"429", "rate limit", "overloaded", "status 500", "status 502", "status 503", "status 504", "status 529",
	"timeout", "i/o timeout", "deadline exceeded", "connection reset", "connection refused", "eof", "temporarily",
}

// IsTransient reports whether err is a transient LLM fault worth a backoff+retry. A permanent
// fault (400/401/403, "no such host", invalid model) is NOT transient and must fail fast.
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
	return false
}
