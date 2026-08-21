package cloudiam

import (
	"testing"
	"time"
)

// The pair BishopFox's control set is built around, reproduced in-tree because the corpus
// is not vendored and CI must still hold the line.
//
//	fn2  Allow iam:CreatePolicyVersion on arn:aws:iam::*:policy/fn2-*    → EXPLOITABLE
//	fp4  Allow iam:CreatePolicyVersion on arn:aws:iam::aws:policy/fp4-*  → NOT exploitable
func TestCandidateResources_AWSOwnedNamespaceIsUnreachable(t *testing.T) {
	customer := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion",
		"Resource":"arn:aws:iam::*:policy/fn2-*"}]}`)
	awsOwned := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion",
		"Resource":"arn:aws:iam::aws:policy/fp4-*"}]}`)

	got := CandidateResources([]*Document{customer}, "123456789012")
	if len(got) != 1 {
		t.Fatalf("customer-managed policy pattern: want 1 candidate, got %v", got)
	}
	if allowed, cond := Allows("iam:CreatePolicyVersion", got[0], customer); !allowed || cond {
		t.Errorf("a grant over a customer-managed policy must be a firm allow; allowed=%v conditional=%v on %s",
			allowed, cond, got[0])
	}

	if got := CandidateResources([]*Document{awsOwned}, "123456789012"); len(got) != 0 {
		t.Errorf("the AWS-owned `aws` namespace holds no customer resource and nothing can "+
			"write to it, so it must yield no candidate; got %v", got)
	}
}

// The old question was asked about the literal resource "*", which no scoped policy
// matches — so a partly-least-privilege grant answered "not allowed" and its escalation
// vanished. This is that regression, stated directly.
func TestCandidateResources_ScopedGrantIsNotInvisible(t *testing.T) {
	d := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy",
		"Resource":"arn:aws:iam::123456789012:user/team-*"}]}`)
	if allowed, _ := Allows("iam:PutUserPolicy", "*", d); allowed {
		t.Fatal("premise changed: `*` should not match a scoped pattern")
	}
	cands := CandidateResources([]*Document{d}, "123456789012")
	found := false
	for _, c := range cands {
		if a, _ := Allows("iam:PutUserPolicy", c, d); a {
			found = true
		}
	}
	if !found {
		t.Errorf("a scoped grant must be reachable through its own candidates; got %v", cands)
	}
}

func TestCandidateResources_EmptyPolicyGrantsNothing(t *testing.T) {
	d := mustDoc(t, `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`)
	if got := CandidateResources([]*Document{d}, "123456789012"); len(got) != 0 {
		t.Errorf("deny statements must seed no candidates — asking whether a principal can "+
			"act where it is forbidden is the wrong question; got %v", got)
	}
}

// A date window that has entirely passed is a DEAD grant, and saying so is the only way a
// permission whose gate expired stops reading as live access. The inverse — a window that
// includes now — is live, because an attacker chooses when to make the request.
func TestDateCondition_ExpiredWindowIsNotAccess(t *testing.T) {
	live := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*",
		"Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:01Z"}}}]}`)
	dead := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*",
		"Condition":{"DateLessThan":{"aws:TokenIssueTime":"2020-01-01T00:00:01Z"}}}]}`)

	if allowed, cond := Allows("iam:CreatePolicyVersion", "*", live); !allowed || cond {
		t.Errorf("a window open since 2020 is satisfiable now and must read as a FIRM allow; allowed=%v conditional=%v", allowed, cond)
	}
	if allowed, _ := Allows("iam:CreatePolicyVersion", "*", dead); allowed {
		t.Error("a window that closed in 2020 grants nothing today and must not read as access")
	}
}

// The refusal that keeps this from becoming a guess: a gate we cannot resolve stays
// unresolved, and the grant stays config-possible rather than confirmed (ADR 0002).
func TestDateCondition_UnresolvableGateStaysConditional(t *testing.T) {
	for _, tc := range []struct{ name, cond string }{
		{"MFA", `{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`},
		{"source IP", `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`},
		{"a date on a key that is not the request clock", `{"DateGreaterThan":{"acme:ContractStart":"2020-01-01T00:00:01Z"}}`},
	} {
		d := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*","Condition":`+tc.cond+`}]}`)
		allowed, cond := Allows("iam:CreatePolicyVersion", "*", d)
		if !allowed || !cond {
			t.Errorf("%s: want a conditional allow, got allowed=%v conditional=%v", tc.name, allowed, cond)
		}
	}
}

// A deny is subject to the same clock. An expired deny does not deny — but note the
// direction: this can only ever ADD a finding, so it is worth stating that a LIVE deny
// still wins outright.
func TestDateCondition_LiveDenyStillWins(t *testing.T) {
	d := mustDoc(t, `{"Statement":[
		{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*"},
		{"Effect":"Deny","Action":"iam:CreatePolicyVersion","Resource":"*",
		 "Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:01Z"}}}]}`)
	if allowed, _ := Allows("iam:CreatePolicyVersion", "*", d); allowed {
		t.Error("a deny whose window is open must still win outright")
	}
}

func TestParseIAMTime_AcceptsBothDocumentedForms(t *testing.T) {
	want := time.Date(2020, 1, 1, 0, 0, 1, 0, time.UTC)
	for _, v := range []string{"2020-01-01T00:00:01Z", "1577836801"} {
		got, err := parseIAMTime(v)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseIAMTime(%q) = %v, %v; want %v", v, got, err, want)
		}
	}
	if _, err := parseIAMTime("whenever"); err == nil {
		t.Error("an unparseable bound must decide nothing, not default to a time")
	}
}
