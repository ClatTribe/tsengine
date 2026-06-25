package webauth

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Replayer runs a LoginFlow against a live target to obtain a session, then validates it — the
// host-side authenticated-scan capability (ADR 0010 Phase 3 wiring) that makes the seed_auth
// reliable. A cookie jar captures the session across the flow's steps; the validation half
// (ValidateSession / IsLoginWall) is what guards against silently scanning logged-out — the FN
// gap. This is authenticated scanning with creds the customer supplied, not active exploitation.
type Replayer struct {
	Client  *http.Client
	MaxBody int64
}

// NewReplayer returns a replayer with a cookie jar (session capture), a bounded timeout, and a
// capped read.
func NewReplayer() *Replayer {
	jar, _ := cookiejar.New(nil)
	return &Replayer{Client: &http.Client{Timeout: 15 * time.Second, Jar: jar}, MaxBody: 256 << 10}
}

// Session is the outcome of a login replay.
type Session struct {
	Valid   bool              `json:"valid"`             // ValidateURL confirmed an authenticated session
	Cookies []*http.Cookie    `json:"-"`                 // captured session cookies (thread into the scan)
	Headers map[string]string `json:"headers,omitempty"` // token-flow auth headers
}

// Login obtains a session by replaying the flow's steps (form/recorded), then probes ValidateURL
// to confirm it's authenticated (Valid). A token flow has no steps — the header IS the session.
// The cookie jar carries the captured session across steps and into the validation probe.
func (rp *Replayer) Login(ctx context.Context, flow LoginFlow) (Session, error) {
	s := Session{Headers: flow.AuthHeaders()}

	for _, step := range flow.Plan() {
		if _, _, err := rp.run(ctx, step, s.Headers); err != nil {
			return s, err
		}
	}

	if flow.ValidateURL != "" {
		status, body, err := rp.run(ctx, Step{Method: http.MethodGet, URL: flow.ValidateURL}, s.Headers)
		if err != nil {
			return s, err
		}
		s.Valid = ValidateSession(status, body, flow)
		if u, perr := url.Parse(flow.ValidateURL); perr == nil && rp.Client.Jar != nil {
			s.Cookies = rp.Client.Jar.Cookies(u)
		}
	}
	return s, nil
}

// run issues one step: POST sends the fields as a form body; otherwise they ride as query params.
func (rp *Replayer) run(ctx context.Context, step Step, authHeaders map[string]string) (int, string, error) {
	target := step.URL
	var body io.Reader
	method := step.Method
	if method == "" {
		method = http.MethodGet
	}
	if len(step.Fields) > 0 {
		vals := url.Values{}
		for k, v := range step.Fields {
			vals.Set(k, v)
		}
		if method == http.MethodGet {
			if strings.Contains(target, "?") {
				target += "&" + vals.Encode()
			} else {
				target += "?" + vals.Encode()
			}
		} else {
			body = strings.NewReader(vals.Encode())
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range step.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range authHeaders {
		req.Header.Set(k, v)
	}
	res, err := rp.Client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	cap := rp.MaxBody
	if cap <= 0 {
		cap = 256 << 10
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, cap))
	return res.StatusCode, string(b), nil
}
