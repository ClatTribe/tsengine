package sspm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func bp(b bool) *bool     { return &b }
func ip(i int) *int       { return &i }
func sp(s string) *string { return &s }

// A hardened org yields nothing; each misconfiguration fires exactly its own rule; an UNREAD setting
// (nil) declines rather than reading as secure.
func TestAssessOkta_FiresOnMisconfigurationAndDeclinesOnUnread(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	hardened := OktaOrg{Name: "acme",
		SignOnRules:   []OktaSignOnRule{{Policy: "Default", Rule: "All users", Status: "ACTIVE", Access: "ALLOW", RequireFactor: bp(true), SessionMinutes: ip(12 * 60), PersistCookie: bp(false)}},
		Passwords:     []OktaPasswordPolicy{{Policy: "Default", Status: "ACTIVE", MinLength: ip(14), LockoutMax: ip(10)}},
		MFAEnroll:     []OktaMFAEnrollPolicy{{Policy: "Default", Status: "ACTIVE", Required: 1, Optional: 2}},
		APITokens:     []OktaAPIToken{{Name: "ci", Created: now.Add(-400 * 24 * time.Hour), LastUsed: now.Add(-2 * 24 * time.Hour)}},
		ThreatInsight: sp("block"), NetworkZones: ip(1)}
	if got := AssessOkta(hardened, Options{Now: now}); len(got) != 0 {
		t.Fatalf("a hardened org must yield nothing, got %d: %+v", len(got), got)
	}

	weak := OktaOrg{Name: "acme",
		SignOnRules: []OktaSignOnRule{
			{Policy: "Legacy", Rule: "Contractors", Status: "ACTIVE", Access: "ALLOW", RequireFactor: bp(false), SessionMinutes: ip(0), PersistCookie: bp(true), NetworkScope: "ANYWHERE"},
			{Policy: "Legacy", Rule: "Disabled", Status: "INACTIVE", Access: "ALLOW", RequireFactor: bp(false)},
			{Policy: "Legacy", Rule: "Deny", Status: "ACTIVE", Access: "DENY", RequireFactor: bp(false)},
		},
		Passwords:     []OktaPasswordPolicy{{Policy: "Default", Status: "ACTIVE", MinLength: ip(8), LockoutMax: ip(0)}},
		MFAEnroll:     []OktaMFAEnrollPolicy{{Policy: "Default", Status: "ACTIVE", Required: 0, Optional: 3}},
		APITokens:     []OktaAPIToken{{Name: "old-script", Created: now.Add(-400 * 24 * time.Hour), LastUsed: now.Add(-200 * 24 * time.Hour), Client: "ops@acme.io"}},
		ThreatInsight: sp("none")}
	got := AssessOkta(weak, Options{Now: now})
	rules := map[string]int{}
	for _, f := range got {
		rules[f.RuleID]++
		if f.Endpoint != "okta:acme" || f.Tool != "sspm" {
			t.Errorf("finding must target the org and come from sspm: %+v", f)
		}
	}
	want := map[string]int{
		"sspm::okta::sign-on-rule-without-mfa":   1, // the ACTIVE ALLOW rule only — not the inactive or the deny
		"sspm::okta::session-lifetime-excessive": 1,
		"sspm::okta::persistent-session-cookie":  1,
		"sspm::okta::password-min-length-short":  1,
		"sspm::okta::password-lockout-disabled":  1,
		"sspm::okta::mfa-enrollment-optional":    1,
		"sspm::okta::api-token-stale":            1,
		"sspm::okta::threatinsight-not-blocking": 1,
	}
	for r, n := range want {
		if rules[r] != n {
			t.Errorf("rule %s fired %d times, want %d (all: %v)", r, rules[r], n, rules)
		}
	}
	if len(got) != 8 {
		t.Errorf("unexpected extra findings: %v", rules)
	}

	// Unread: nothing reported → nothing fires. This is the difference between "secure" and "unseen".
	unread := OktaOrg{Name: "acme", SignOnRules: []OktaSignOnRule{{Policy: "P", Rule: "R", Status: "ACTIVE", Access: "ALLOW"}},
		Passwords: []OktaPasswordPolicy{{Policy: "P", Status: "ACTIVE"}}, Unread: map[string]string{"threats/configuration": "HTTP 403"}}
	if got := AssessOkta(unread, Options{Now: now}); len(got) != 0 {
		t.Errorf("unread settings must decline, not fire: %+v", got)
	}
}

// The fetcher reads the org's documented shapes, pages the policy lists, names what it cannot
// read, and refuses to produce an org when nothing was readable.
func TestFetchOktaPosture_ReadsPoliciesTokensAndThreatInsightAndNamesUnread(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no token", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "OKTA_SIGN_ON":
			w.Write([]byte(`[{"id":"p1","name":"Default Policy","status":"ACTIVE"}]`))
		case r.URL.Path == "/api/v1/policies/p1/rules":
			w.Write([]byte(`[{"name":"Default Rule","status":"ACTIVE","conditions":{"network":{"connection":"ANYWHERE"}},
			  "actions":{"signon":{"access":"ALLOW","requireFactor":false,"session":{"maxSessionLifetimeMinutes":0,"usePersistentCookie":true}}}}]`))
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "PASSWORD":
			w.Write([]byte(`[{"id":"pw1","name":"Default Policy","status":"ACTIVE","settings":{"password":{"complexity":{"minLength":8,"minLowerCase":1,"minUpperCase":1,"minNumber":1,"minSymbol":0,"dictionary":{"common":{"exclude":false}}},"lockout":{"maxAttempts":0}}}}]`))
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "MFA_ENROLL":
			w.Write([]byte(`[{"id":"m1","name":"Default Policy","status":"ACTIVE","settings":{"factors":{"okta_otp":{"enroll":{"self":"OPTIONAL"}},"okta_push":{"enroll":{"self":"OPTIONAL"}}}}}]`))
		case r.URL.Path == "/api/v1/api-tokens":
			w.Write([]byte(`[{"name":"terraform","created":"2025-01-01T00:00:00.000Z","lastUpdated":"2026-01-01T00:00:00.000Z","clientName":"Terraform"}]`))
		case r.URL.Path == "/api/v1/threats/configuration":
			http.Error(w, `{"errorCode":"E0000006"}`, 403) // not licensed / no scope → unread, not "block"
		case r.URL.Path == "/api/v1/zones":
			w.Write([]byte(`[{"id":"z1"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	org, err := FetchOktaPosture(context.Background(), srv.URL, "acme", "tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(org.SignOnRules) != 1 || !isFalse(org.SignOnRules[0].RequireFactor) || *org.SignOnRules[0].SessionMinutes != 0 || !isTrue(org.SignOnRules[0].PersistCookie) {
		t.Errorf("sign-on rule: %+v", org.SignOnRules)
	}
	if len(org.Passwords) != 1 || *org.Passwords[0].MinLength != 8 || *org.Passwords[0].LockoutMax != 0 || *org.Passwords[0].Complexity != 3 {
		t.Errorf("password policy: %+v", org.Passwords[0])
	}
	if len(org.MFAEnroll) != 1 || org.MFAEnroll[0].Required != 0 || org.MFAEnroll[0].Optional != 2 {
		t.Errorf("mfa enroll: %+v", org.MFAEnroll)
	}
	if len(org.APITokens) != 1 || org.APITokens[0].Client != "Terraform" {
		t.Errorf("api tokens: %+v", org.APITokens)
	}
	if org.ThreatInsight != nil || !strings.Contains(org.Unread["threats/configuration"], "403") {
		t.Errorf("an unreadable ThreatInsight must be nil and NAMED: ti=%v unread=%v", org.ThreatInsight, org.Unread)
	}
	if org.NetworkZones == nil || *org.NetworkZones != 1 {
		t.Errorf("zones: %v", org.NetworkZones)
	}
	// The assessor over what was read fires the weak-config rules and stays silent on ThreatInsight.
	rules := map[string]bool{}
	for _, f := range AssessOkta(org, Options{Now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}) {
		rules[f.RuleID] = true
	}
	for _, want := range []string{"sspm::okta::sign-on-rule-without-mfa", "sspm::okta::password-min-length-short", "sspm::okta::mfa-enrollment-optional", "sspm::okta::api-token-stale"} {
		if !rules[want] {
			t.Errorf("expected %s over the fetched org; fired %v", want, rules)
		}
	}
	if rules["sspm::okta::threatinsight-not-blocking"] {
		t.Error("ThreatInsight was unread and must not fire")
	}

	// Nothing readable is an error, not an org with no findings.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 403) }))
	defer dead.Close()
	if _, err := FetchOktaPosture(context.Background(), dead.URL, "acme", "tok", dead.Client()); err == nil {
		t.Fatal("a token that reaches no endpoint must be an error")
	}
}
