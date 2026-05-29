// Package seedauth captures a web session so downstream tools can scan
// behind a login. It's tsengine's L1 auth flow — the deterministic
// (non-LLM) counterpart to strix's scan_auth_flow.
//
// Two modes:
//   - provided session: args["cookie"] is passed straight through.
//   - form login: POST username/password to args["login_url"], capture
//     the Set-Cookie response header.
//
// The captured cookie rides back in Result.CapturedSession; the
// orchestrator threads it into the later (authed) dispatch wave. Because
// the authed scanners depend on seed_auth (deps.go), the W3 wave
// classifier guarantees this runs first — the race strix hit with
// unguarded parallel auth (Q4.2) is impossible here.
//
// Deliberately thin: single-step form POST only. CSRF-token flows,
// multi-step login, and SPA/JS login are documented backlog, not built.
package seedauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// SeedAuth is the tool.Tool implementation.
type SeedAuth struct{}

// New constructs a SeedAuth wrapper.
func New() *SeedAuth { return &SeedAuth{} }

// Name is "seed_auth" to match the dependency table in deps.go.
func (*SeedAuth) Name() string              { return "seed_auth" }
func (*SeedAuth) SandboxExecution() bool    { return true }
func (*SeedAuth) MITRETechniques() []string { return []string{"T1078"} }

// Run resolves a session. Recognized args:
//
//	"cookie"         string — pre-obtained session → passthrough.
//	"login_url"      string — form-login POST target.
//	"username"/"password"   — credentials.
//	"username_field"/"password_field" — form field names (defaults).
//
// Returns the captured cookie in Result.CapturedSession.
func (*SeedAuth) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	if c, _ := args["cookie"].(string); strings.TrimSpace(c) != "" {
		return tool.Result{Output: "provided session", CapturedSession: c}, nil
	}

	loginURL, _ := args["login_url"].(string)
	if strings.TrimSpace(loginURL) == "" {
		return tool.Result{}, errors.New("seed_auth: need 'cookie' or 'login_url'")
	}
	cookie, err := formLogin(ctx, args, loginURL)
	if err != nil {
		// Auth failure shouldn't crash the scan — surface it, return no
		// session (downstream tools then scan unauthenticated).
		return tool.Result{Output: "form login failed: " + err.Error()}, nil
	}
	return tool.Result{Output: "form login captured session", CapturedSession: cookie}, nil
}

func formLogin(ctx context.Context, args tool.Args, loginURL string) (string, error) {
	uf := strOr(args["username_field"], "username")
	pf := strOr(args["password_field"], "password")
	form := url.Values{}
	form.Set(uf, strOr(args["username"], ""))
	form.Set(pf, strOr(args["password"], ""))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Don't follow redirects — the Set-Cookie usually rides the 302.
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return "", fmt.Errorf("no Set-Cookie in login response (status %d)", resp.StatusCode)
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), nil
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func init() { tool.Register(New()) }
