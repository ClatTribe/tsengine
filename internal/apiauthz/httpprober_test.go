package apiauthz

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type flakyRT struct {
	failN int
	err   error
	calls int
}

func (f *flakyRT) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls++
	if f.calls <= f.failN {
		return nil, f.err
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody}, nil
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial tcp: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestHTTPProber_RetriesTransientThenSucceeds(t *testing.T) {
	rt := &flakyRT{failN: 2, err: timeoutErr{}}
	h := &HTTPProber{Client: &http.Client{Transport: rt}, MaxBody: 1 << 10, Retries: 2}
	res, err := h.Do(context.Background(), Request{URL: "http://api.example/orders/1"})
	if err != nil {
		t.Fatalf("two transient timeouts should be retried: %v", err)
	}
	if res.Status != 200 || rt.calls != 3 {
		t.Errorf("want 200 after 3 round-trips, got status=%d calls=%d", res.Status, rt.calls)
	}
}

func TestHTTPProber_PermanentFailsFast(t *testing.T) {
	rt := &flakyRT{failN: 5, err: errors.New("connect: connection refused")}
	h := &HTTPProber{Client: &http.Client{Transport: rt}, MaxBody: 1 << 10, Retries: 2}
	if _, err := h.Do(context.Background(), Request{URL: "http://api.example/orders/1"}); err == nil {
		t.Error("connection refused must fail fast")
	}
	if rt.calls != 1 {
		t.Errorf("permanent fault must not retry, got %d", rt.calls)
	}
}
