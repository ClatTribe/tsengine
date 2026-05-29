package adapters

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/l2"
)

// HTTPDoer is the L2 send_request primitive: a SINGLE, bounded HTTP request to
// CONFIRM a finding (e.g. re-request a reflected-XSS URL and check the payload
// echoes back). Verification, not exploitation — so it is intentionally
// minimal: scheme allow-list, hard timeout, capped body read, bounded
// redirects. strix hands the LLM a full Burp-style proxy/repeater
// (send_request/repeat_request); the translator only needs to confirm, so
// this stays a deliberately thin primitive.
type HTTPDoer struct {
	client  *http.Client
	maxBody int64
}

var _ l2.HTTPDoer = (*HTTPDoer)(nil)

const (
	defaultHTTPTimeout = 15 * time.Second
	defaultMaxBody     = 64 << 10 // 64 KiB — enough to spot a reflected payload
	maxRedirects       = 5
)

// NewHTTPDoer builds the bounded verification client.
func NewHTTPDoer() *HTTPDoer {
	return &HTTPDoer{
		client: &http.Client{
			Timeout: defaultHTTPTimeout,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				return nil
			},
		},
		maxBody: defaultMaxBody,
	}
}

// Do implements l2.HTTPDoer. Only http/https are allowed; the body is read up
// to maxBody. Returns a status + salient-headers + truncated-body summary.
func (d *HTTPDoer) Do(ctx context.Context, method, rawURL string, headers map[string]string, body string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q (only http/https allowed)", u.Scheme)
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, d.maxBody))
	return renderHTTP(resp, b), nil
}

func renderHTTP(resp *http.Response, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %s\n", resp.Status)
	for _, h := range []string{"Content-Type", "Location", "Server", "Set-Cookie", "Content-Length"} {
		if v := resp.Header.Get(h); v != "" {
			fmt.Fprintf(&b, "%s: %s\n", h, v)
		}
	}
	fmt.Fprintf(&b, "--- body (%d bytes shown) ---\n%s", len(body), string(body))
	return b.String()
}
