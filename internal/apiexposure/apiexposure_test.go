package apiexposure

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func ruleIDs(fs []types.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

// A clean API produces nothing. If this ever fails the package is a noise generator.
func TestCleanResponseYieldsNothing(t *testing.T) {
	got := Assess([]Response{
		{Endpoint: "/v1/status", Status: 200, Body: `{"status":"ok","uptime_seconds":4210,"version":"1.4.2"}`},
		{Endpoint: "/v1/items", Status: 200, Body: `{"items":[{"id":1,"title":"Widget"},{"id":2,"title":"Gadget"}]}`},
	})
	if len(got) != 0 {
		t.Fatalf("clean responses produced %v", ruleIDs(got))
	}
}

// THE GROUNDING LINE, both directions. The same body is a vulnerability when it comes
// back without credentials and an observation when it does not. Getting this backwards
// either floods a customer with findings about their own profile endpoint, or misses
// the case that actually matters.
func TestPersonalDataVerdictTurnsOnAuthentication(t *testing.T) {
	body := `{"users":[{"email":"ada@example.com","ssn":"219-09-9999"},{"email":"bob@example.com","ssn":"457-55-5462"}]}`

	unauth := Assess([]Response{{Endpoint: "/api/users", Status: 200, Body: body, Authenticated: false}})
	if len(unauth) != 1 || unauth[0].RuleID != RuleUnauthPersonal {
		t.Fatalf("unauthenticated: got %v, want one %s", ruleIDs(unauth), RuleUnauthPersonal)
	}
	if unauth[0].Severity != types.SeverityHigh {
		t.Errorf("unauthenticated personal data should be high, got %s", unauth[0].Severity)
	}

	auth := Assess([]Response{{Endpoint: "/api/users", Status: 200, Body: body, Authenticated: true}})
	if len(auth) != 1 || auth[0].RuleID != RuleObservation {
		t.Fatalf("authenticated: got %v, want one %s", ruleIDs(auth), RuleObservation)
	}
	if auth[0].Severity != types.SeverityInfo {
		t.Errorf("an authenticated caller may be entitled to this; severity must be info, got %s", auth[0].Severity)
	}
}

// A credential in a body is a finding for ANY caller. An authenticated user is not
// entitled to a password hash either.
func TestCredentialIsAFindingEvenWhenAuthenticated(t *testing.T) {
	for _, authed := range []bool{false, true} {
		got := Assess([]Response{{
			Endpoint: "/api/users/me", Status: 200, Authenticated: authed,
			Body: `{"username":"ada","password":"5f4dcc3b5aa765d61d8327deb882cf99"}`,
		}})
		if len(got) != 1 || got[0].RuleID != RuleCredential {
			t.Fatalf("authenticated=%v: got %v, want %s", authed, ruleIDs(got), RuleCredential)
		}
		if got[0].Severity != types.SeverityHigh {
			t.Errorf("authenticated=%v: credential exposure must be high, got %s", authed, got[0].Severity)
		}
	}
}

// The finding is about leaked data and must not itself leak any. dataclass guarantees
// this; the test pins that the glue does not undo it by pasting the body in.
func TestFindingNeverEchoesAValue(t *testing.T) {
	const ssn = "219-09-9999"
	const email = "ada@example.com"
	got := Assess([]Response{{
		Endpoint: "/api/users", Status: 200,
		Body: `{"email":"` + email + `","ssn":"` + ssn + `"}`,
	}})
	if len(got) == 0 {
		t.Fatal("expected a finding")
	}
	blob := got[0].Title + " " + got[0].Description
	for _, secret := range []string{ssn, email} {
		if strings.Contains(blob, secret) {
			t.Errorf("the finding echoes %q — a report about exposed data must not expose it", secret)
		}
	}
}

// Array elements must COLLAPSE onto one column name, or every field carries a single
// value and dataclass systematically under-confirms — reporting Suspected where the
// data itself proves Confirmed.
func TestArrayElementsCollapseIntoOneSampledColumn(t *testing.T) {
	cols := columnsFromJSON(`{"users":[{"card":"4111111111111111"},{"card":"5500005555555559"},{"card":"340000000000009"}]}`)
	var found bool
	for _, c := range cols {
		if c.Name == "card" {
			found = true
			if len(c.Values) != 3 {
				t.Fatalf("card column carries %d values, want 3 — array elements did not collapse", len(c.Values))
			}
		}
	}
	if !found {
		t.Fatalf("no 'card' column; got %v", cols)
	}
}

// A name with no usable value must still reach the classifier: a field called
// "password" that is null is still a field called "password".
func TestNamedFieldSurvivesANullValue(t *testing.T) {
	cols := columnsFromJSON(`{"password":null,"ok":true}`)
	var names []string
	for _, c := range cols {
		names = append(names, c.Name)
	}
	if len(names) != 2 {
		t.Fatalf("got columns %v, want both names present even with no classifiable values", names)
	}
}

// Non-JSON is not guessed at. Inferring a shape from HTML or a stack trace would be
// invention, not classification.
func TestNonJSONYieldsNothing(t *testing.T) {
	for _, body := range []string{"", "   ", "<html><body>ada@example.com</body></html>", "boom: ssn=219-09-9999"} {
		if got := Assess([]Response{{Endpoint: "/x", Status: 200, Body: body}}); len(got) != 0 {
			t.Errorf("body %q produced %v; non-JSON must not be parsed by guesswork", body, ruleIDs(got))
		}
	}
}

// Every finding must carry its OWASP item, or the per-item scoreboard cannot count it.
func TestFindingsCarryTheirOWASPItem(t *testing.T) {
	got := Assess([]Response{
		{Endpoint: "/a", Status: 200, Body: `{"password":"5f4dcc3b5aa765d61d8327deb882cf99"}`},
		{Endpoint: "/b", Status: 200, Body: `{"ssn":"219-09-9999"}`},
	})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	for _, f := range got {
		if f.ToolArgs["owasp_api"] != "API3" {
			t.Errorf("%s carries owasp_api=%q, want API3", f.RuleID, f.ToolArgs["owasp_api"])
		}
	}
}
