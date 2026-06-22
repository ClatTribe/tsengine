package llmretry

import (
	"errors"
	"testing"
)

func TestIsTransient(t *testing.T) {
	for _, s := range []string{"anthropic: status 429: x", "status 503", "overloaded", "context deadline exceeded", "connection reset by peer", "status 529", "i/o timeout"} {
		if !IsTransient(errors.New(s)) {
			t.Errorf("%q should be transient (retryable)", s)
		}
	}
	for _, s := range []string{"anthropic: status 400: bad request", "status 401: unauthorized", "no such host", "invalid model"} {
		if IsTransient(errors.New(s)) {
			t.Errorf("%q should NOT be transient (fail fast)", s)
		}
	}
	if IsTransient(nil) {
		t.Error("nil error is not transient")
	}
}
