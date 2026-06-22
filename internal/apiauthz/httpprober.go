package apiauthz

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/nettransient"
)

// HTTPProber is the live Prober for the BOLA/BFLA differential test (ADR 0010 Phase 1 wiring).
// It sends the per-identity request (the victim's auth headers, then the attacker's) with a
// bounded timeout + a capped response read, so the engine can compare the two responses. Benign
// by construction at the apiauthz layer (it replays the victim's OWN object request as the
// attacker; reads, never writes/exfils) — but it IS live traffic to a customer's API, so it is
// gated (see LiveProber).
type HTTPProber struct {
	Client  *http.Client
	MaxBody int64 // cap on bytes read from the response (default 64 KiB)
	// Retries is how many extra times a request is re-sent on a TRANSIENT transport fault.
	// The BOLA/BFLA test is a DIFFERENTIAL over two responses (victim then attacker); a single
	// network blip on either would silently produce a wrong verdict — almost always a
	// false-negative (a real authz bypass missed). 0 → no retry. A permanent fault fails fast.
	Retries int
}

// NewHTTPProber returns a prober with safe defaults (8s timeout, 64 KiB read cap, 2 transient
// retries). Redirects are followed (an authz check cares about the final status+body, unlike the
// open-redirect proof).
func NewHTTPProber() *HTTPProber {
	return &HTTPProber{Client: &http.Client{Timeout: 8 * time.Second}, MaxBody: 64 << 10, Retries: 2}
}

// Do issues one request (with bounded transient-transport retry) with the identity's headers and
// returns the status + (capped) body. A transient blip is retried so it can't flip a differential
// verdict; a permanent fault fails fast.
func (h *HTTPProber) Do(ctx context.Context, r Request) (Response, error) {
	for attempt := 0; ; attempt++ {
		res, err := h.do1(ctx, r)
		if err == nil || !nettransient.IsTransient(err) || attempt >= h.Retries {
			return res, err
		}
		t := time.NewTimer(time.Duration(200<<attempt) * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return Response{}, ctx.Err()
		case <-t.C:
		}
	}
}

// do1 issues a single request (no retry).
func (h *HTTPProber) do1(ctx context.Context, r Request) (Response, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		return Response{}, err
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "tsengine-apiauthz/1.0 (authorized authz test)")
	res, err := h.Client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	cap := h.MaxBody
	if cap <= 0 {
		cap = 64 << 10
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, cap))
	return Response{Status: res.StatusCode, Body: string(b)}, nil
}

// LiveProber returns a live HTTPProber ONLY when the operator has explicitly enabled active
// testing (TSENGINE_ACTIVE_EXPLOIT=1) — sending requests to a customer's API is active testing
// and requires consent (the ADR 0006/0008 gate, shared with the pentest active driver).
// Otherwise it returns nil, so Run reports the plan as un-run leads — never a falsely-confident
// result from traffic that was never sent.
func LiveProber() Prober {
	if os.Getenv("TSENGINE_ACTIVE_EXPLOIT") == "1" {
		return NewHTTPProber()
	}
	return nil
}
