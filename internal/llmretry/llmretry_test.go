package llmretry

import (
	"errors"
	"testing"
)

func TestIsTransient(t *testing.T) {
	transient := []string{
		// keyword signals
		"overloaded", "context deadline exceeded", "connection reset by peer", "i/o timeout",
		"rate limit exceeded", "server temporarily unavailable",
		// "status <code>" spelling
		"anthropic: status 429: x", "status 503", "status 529", "status: 500",
		// "HTTP <code>" spelling — the format EVERY client in this tree actually emits.
		// These are the cases the old "status 5xx"-only list silently missed (5xx read as
		// permanent → agent loop broke on a throttle window).
		"opencode: HTTP 429", "opencode: HTTP 500", "opencode: HTTP 502", "opencode: HTTP 503",
		"opencode: create session: HTTP 500 decode failed",
		"anthropic: claude-x returned HTTP 529", "gemini: g returned HTTP 503",
		"openai-compat: m returned HTTP 500",
	}
	for _, s := range transient {
		if !IsTransient(errors.New(s)) {
			t.Errorf("%q should be transient (retryable)", s)
		}
	}

	permanent := []string{
		"anthropic: status 400: bad request", "status 401: unauthorized", "no such host", "invalid model",
		"opencode: HTTP 400", "opencode: HTTP 401", "opencode: HTTP 404", "gemini: g returned HTTP 403",
		// a bare number that is NOT an HTTP status must not trip the retry
		"opencode: empty response", "read 500 bytes then closed", "listening on port 5031",
	}
	for _, s := range permanent {
		if IsTransient(errors.New(s)) {
			t.Errorf("%q should NOT be transient (fail fast)", s)
		}
	}

	if IsTransient(nil) {
		t.Error("nil error is not transient")
	}
}
