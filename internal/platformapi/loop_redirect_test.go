package platformapi

import "testing"

// An authorize URL is only usable if BOTH halves are configured: the provider's credentials AND this
// deployment's own public address. The credentials guard existed; this one did not.
//
// With TSENGINE_PLATFORM_PUBLIC unset the redirect became the relative "/v1/connect/github/callback".
// Every OAuth provider requires an absolute redirect_uri, so a customer clicking Connect was sent to
// the provider and bounced onto its error page — the exact failure the credentials guard was written
// to prevent, one level down.
func TestRedirectIsAbsolute(t *testing.T) {
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{"relative redirect — the bug", "https://github.com/login/oauth/authorize?client_id=x&redirect_uri=%2Fv1%2Fconnect%2Fgithub%2Fcallback", false},
		{"absolute redirect", "https://github.com/login/oauth/authorize?client_id=x&redirect_uri=https%3A%2F%2Fapp.acme.com%2Fv1%2Fconnect%2Fgithub%2Fcallback", true},
		// The cloud connectors are console / CloudFormation links with no redirect_uri at all, and
		// must keep working on a deployment that has no public URL.
		{"no redirect_uri at all (cloud console link)", "https://console.aws.amazon.com/cloudformation/home?stackName=x", true},
		{"scheme but no host", "https://x/authorize?redirect_uri=https%3A%2F%2F", false},
		{"host but no scheme", "https://x/authorize?redirect_uri=app.acme.com%2Fcb", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := redirectIsAbsolute(c.url)
			if c.ok && err != nil {
				t.Errorf("rejected a usable authorize URL: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("accepted an authorize URL the provider will reject")
			}
		})
	}
}
