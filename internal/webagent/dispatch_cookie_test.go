package webagent

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type capturingDispatcher struct{ got map[string]any }

func (c *capturingDispatcher) RunTool(_ context.Context, _ string, args map[string]any) (string, error) {
	c.got = args
	return "ok", nil
}

// TestDispatchOSS_InjectsAuthenticatedSession: an authed IDOR/SQLi sweep via dispatch_oss must carry the
// login the agent already established. Before this, ffuf/sqlmap ran UNAUTHENTICATED and hit the login
// wall (grounded: ffuf got 302→/login for every id). tDispatchOSS must inject the agent's session
// cookie into the tool args — unless the agent set one explicitly.
func TestDispatchOSS_InjectsAuthenticatedSession(t *testing.T) {
	r := NewRequester([]string{"app.test"}, 100, 0)
	u, _ := url.Parse("http://app.test/")
	r.jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "SECRET123"}})

	fake := &capturingDispatcher{}
	cc := &Context{ctx: context.Background(), req: r, dispatcher: fake}

	tDispatchOSS(cc, map[string]any{
		"tool": "ffuf",
		"args": map[string]any{"url": "http://app.test/order/FUZZ/receipt", "range": "1-10"},
	})
	if fake.got == nil {
		t.Fatal("dispatcher was not called")
	}
	if got, _ := fake.got["cookie"].(string); got != "session=SECRET123" {
		t.Errorf("session cookie not injected into dispatch args: got %q", got)
	}

	// an EXPLICIT cookie from the agent (e.g. a forged token) must NOT be overridden.
	fake2 := &capturingDispatcher{}
	cc2 := &Context{ctx: context.Background(), req: r, dispatcher: fake2}
	tDispatchOSS(cc2, map[string]any{
		"tool": "ffuf",
		"args": map[string]any{"url": "http://app.test/x/FUZZ", "cookie": "session=FORGED"},
	})
	if got, _ := fake2.got["cookie"].(string); got != "session=FORGED" {
		t.Errorf("explicit cookie must be preserved, got %q", got)
	}
	_ = time.Second
}
