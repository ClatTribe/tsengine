package webagent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// creds.go gives the agent a bounded default-credential check — one of the most common real-world
// footholds (admin/admin, admin/password, …). try_default_creds establishes a KNOWN-BAD-credential
// baseline, then tries a small curated list and flags a hit ONLY on a grounded DIFFERENTIAL vs that
// baseline (a redirect the bad login didn't get, or a session-ish cookie it didn't set). So a hit is
// real, never guessed (§10) — a login that returns the same failure shape for every pair yields
// nothing. It's a bounded CHECK (capped by the request budget), not a brute-force spray; §13-clean
// exploitation tooling (the on-demand equivalent of the ip-asset hydra escalation).

type credPair struct{ user, pass string }

// defaultCreds is a short, high-signal list of the credential pairs that show up as vendor/app
// defaults. Kept small on purpose (a full wordlist is hydra's job); tuned for the common web defaults.
var defaultCreds = []credPair{
	{"admin", "admin"}, {"admin", "password"}, {"admin", ""}, {"admin", "admin123"},
	{"admin", "changeme"}, {"admin", "123456"}, {"admin", "letmein"}, {"admin", "secret"},
	{"admin", "pass"}, {"admin", "12345"}, {"administrator", "administrator"},
	{"administrator", "password"}, {"root", "root"}, {"root", "toor"}, {"root", "password"},
	{"test", "test"}, {"guest", "guest"}, {"user", "user"}, {"tomcat", "tomcat"}, {"sa", ""},
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return strings.TrimSpace(s)
}

func argBool(args map[string]any, k string) bool {
	switch v := args[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// sessionishCookieNames returns the Set-Cookie names that look like an auth/session cookie — the ones
// whose PRESENCE (when a failed login lacked them) is a real login-success signal.
func sessionishCookieNames(raw []string) []string {
	var out []string
	for _, c := range raw {
		ln := strings.ToLower(cookieName(c))
		for _, kw := range []string{"sess", "auth", "token", "sid", "jwt", "login", "user"} {
			if strings.Contains(ln, kw) {
				out = append(out, cookieName(c))
				break
			}
		}
	}
	return out
}

func containsStr(xs []string, x string) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}

// credPost submits one username/password pair to the login endpoint (form-urlencoded by default, JSON
// when asJSON) through the scoped Requester (budget-counted + allowlisted).
func (cc *Context) credPost(loginURL, userField, passField, user, pass string, asJSON bool) (*Resp, error) {
	var body string
	headers := map[string]string{}
	if asJSON {
		b, _ := json.Marshal(map[string]string{userField: user, passField: pass})
		body = string(b)
		headers["Content-Type"] = "application/json"
	} else {
		body = url.Values{userField: {user}, passField: {pass}}.Encode()
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	return cc.req.Send(cc.ctx, "POST", loginURL, body, headers)
}

// tDefaultCreds tries the default-cred list against a login endpoint, reporting the first pair that
// produces a grounded login-success differential vs a known-bad baseline.
func tDefaultCreds(cc *Context, args map[string]any) string {
	loginURL := strings.TrimSpace(argStr(args, "url"))
	if loginURL == "" {
		return "ERROR: url is required (the login endpoint that accepts the username/password POST)"
	}
	userField := orDefault(argStr(args, "user_field"), "username")
	passField := orDefault(argStr(args, "pass_field"), "password")
	asJSON := argBool(args, "json")

	// Baseline: a random-junk credential — what a FAILED login looks like on this endpoint.
	base, err := cc.credPost(loginURL, userField, passField, "zzq"+randHex(4), "wrong"+randHex(3), asJSON)
	if err != nil {
		return "REQUEST FAILED (baseline): " + err.Error()
	}
	baseSess := sessionishCookieNames(base.SetCookie)

	tried := 0
	for _, c := range defaultCreds {
		resp, err := cc.credPost(loginURL, userField, passField, c.user, c.pass, asJSON)
		if err != nil { // budget exhausted / network — stop with what we have
			return fmt.Sprintf("stopped after %d attempt(s): %v", tried, err)
		}
		tried++

		// Grounded success = a DIFFERENTIAL win vs the failed baseline:
		//   (a) a redirect the baseline didn't get (or to a different place), or
		//   (b) an auth/session cookie the baseline didn't set.
		redirectWin := isRedirect(resp.Status) && (!isRedirect(base.Status) || resp.Location != base.Location)
		newCookie := ""
		for _, n := range sessionishCookieNames(resp.SetCookie) {
			if !containsStr(baseSess, n) {
				newCookie = n
				break
			}
		}
		if !redirectWin && newCookie == "" {
			continue
		}

		why := ""
		switch {
		case redirectWin && resp.Location != "":
			why = fmt.Sprintf("login redirected to %s (the failed baseline did not)", capLine(resp.Location, 120))
		case redirectWin:
			why = fmt.Sprintf("login returned %d (the failed baseline did not redirect)", resp.Status)
		default:
			why = fmt.Sprintf("login set a new session cookie %q the failed baseline did not", newCookie)
		}
		cc.turnN++
		cc.History = append(cc.History, Turn{
			ID: fmt.Sprintf("t-%03d", cc.turnN), Method: "POST(login)", URL: loginURL,
			Body: userField + "=" + c.user + "&" + passField + "=" + strings.Repeat("*", len(c.pass)),
			Status: resp.Status, Indicators: []string{"default_creds"}, Elapsed: resp.Elapsed.String(),
			RespSnippet: why,
		})
		pw := c.pass
		if pw == "" {
			pw = "(empty)"
		}
		return fmt.Sprintf("t-%03d  DEFAULT CREDENTIALS WORK: %s:%s on %s — %s. Log in with these (send_request) to reach the authenticated surface; record class=default_credentials citing t-%03d.",
			cc.turnN, c.user, pw, loginURL, why, cc.turnN)
	}
	return fmt.Sprintf("no default credentials worked (%d pairs tried) — the login returns the same failure shape for all of them; try app-specific creds, a filter bypass, or another vector.", tried)
}
