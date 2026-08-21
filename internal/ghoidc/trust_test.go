package ghoidc

import (
	"strings"
	"testing"
)

func trust(cond string) []byte {
	return []byte(`{"Version":"2012-10-17","Statement":[{
      "Sid":"GH","Effect":"Allow",
      "Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
      "Action":"sts:AssumeRoleWithWebIdentity"` + cond + `}]}`)
}

func kinds(a Analysis) map[string]string {
	m := map[string]string{}
	for _, w := range a.Weaknesses {
		m[w.Kind] = w.Severity
	}
	return m
}

func TestAnalyze_NoSubjectConditionIsCritical(t *testing.T) {
	a := Analyze(trust(`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`))
	if !a.Parsed || !a.TrustsGitHub {
		t.Fatal("should have parsed a GitHub-trusting statement")
	}
	if sev := kinds(a)[SubjectUnconstrained]; sev != "critical" {
		t.Fatalf("a trust policy with no sub condition lets ANY repo assume the role; got %q", sev)
	}
}

// THE LOAD-BEARING REFUSAL. `*` is a wildcard under StringLike and a literal under
// StringEquals. A scanner that counted asterisks would raise a critical against a
// policy that actually fails closed.
func TestAnalyze_AsteriskUnderStringEqualsIsNotAWildcard(t *testing.T) {
	a := Analyze(trust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
       "token.actions.githubusercontent.com:sub":"repo:acme/*"}}`))
	if k := kinds(a); k[SubjectSpansRepositories] != "" {
		t.Fatalf("StringEquals treats `*` literally — this policy matches a repo named `*`, "+
			"i.e. nothing. Reporting %q is a false positive", k[SubjectSpansRepositories])
	}
}

func TestAnalyze_AsteriskUnderStringLikeIsAWildcard(t *testing.T) {
	a := Analyze(trust(`,"Condition":{
       "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
       "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`))
	if sev := kinds(a)[SubjectSpansRepositories]; sev != "high" {
		t.Fatalf("every repo in the org can assume this role; got %q", sev)
	}
}

func TestAnalyze_SubjectScopeSeverityLadder(t *testing.T) {
	for _, tc := range []struct {
		sub      string
		kind     string
		severity string
	}{
		{"*", SubjectSpansRepositories, "critical"},                              // anything at all
		{"repo:*", SubjectSpansRepositories, "critical"},                         // any owner
		{"repo:*/api:ref:refs/heads/main", SubjectSpansRepositories, "critical"}, // any owner, fixed repo name
		{"repo:acme/*", SubjectSpansRepositories, "high"},                        // any repo in org
		{"repo:acme/api:*", SubjectSpansRefs, "medium"},                          // any ref of one repo
		{"repo:acme/api:ref:refs/heads/*", SubjectSpansRefs, "medium"},           // any branch
	} {
		a := Analyze(trust(`,"Condition":{
           "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
           "StringLike":{"token.actions.githubusercontent.com:sub":"` + tc.sub + `"}}`))
		if got := kinds(a)[tc.kind]; got != tc.severity {
			t.Errorf("sub=%q: want %s=%s, got %q (all: %v)", tc.sub, tc.kind, tc.severity, got, kinds(a))
		}
	}
}

func TestAnalyze_ExactSubjectAndAudienceIsClean(t *testing.T) {
	a := Analyze(trust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	if len(a.Weaknesses) != 0 {
		t.Fatalf("a correctly pinned trust policy must yield ZERO findings, got %+v", a.Weaknesses)
	}
}

// Grounding: only GitHub, only Allow, only web-identity.
func TestAnalyze_IgnoresWhatIsNotAGitHubWebIdentityAllow(t *testing.T) {
	for name, doc := range map[string]string{
		"another provider": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity",
            "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/gitlab.com"}}]}`,
		"a deny": `{"Statement":[{"Effect":"Deny","Action":"sts:AssumeRoleWithWebIdentity",
            "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"}}]}`,
		"a plain AWS role trust": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
            "Principal":{"AWS":"arn:aws:iam::1:root"}}]}`,
	} {
		a := Analyze([]byte(doc))
		if a.TrustsGitHub || len(a.Weaknesses) != 0 {
			t.Errorf("%s must produce no GitHub-OIDC finding, got %+v", name, a.Weaknesses)
		}
	}
}

// "We could not look" must never read as "we looked and it was clean."
func TestAnalyze_UnparseablePolicyIsNotParsedAndNotClean(t *testing.T) {
	a := Analyze([]byte(`{"Statement": <<<broken`))
	if a.Parsed {
		t.Fatal("a broken document must report Parsed=false")
	}
	if len(a.Weaknesses) != 0 {
		t.Fatal("a document we could not read must not produce findings")
	}
}

// A policy pinned via `repository` rather than `sub` is constrained — narrower than
// nothing — so it must NOT be reported as "any repo can assume".
func TestAnalyze_RepositoryClaimPinIsNotReportedAsUnconstrained(t *testing.T) {
	a := Analyze(trust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
       "token.actions.githubusercontent.com:repository":"acme/api"}}`))
	k := kinds(a)
	if k[SubjectUnconstrained] != "" {
		t.Fatal("the repository claim pins WHICH repo — calling this unconstrained is a false positive")
	}
	if k[SubjectSpansRefs] != "medium" {
		t.Fatalf("refs are still unbounded, so the lesser finding must fire; got %v", k)
	}
}

func TestAnalyze_MissingAudienceIsItsOwnFinding(t *testing.T) {
	a := Analyze(trust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	if sev := kinds(a)[AudienceUnconstrained]; sev != "medium" {
		t.Fatalf("missing aud is its own finding with its own fix; got %q", sev)
	}
}

// ForAnyValue:/ForAllValues: prefixes must not hide a wildcard.
func TestAnalyze_SetOperatorPrefixDoesNotHideAWildcard(t *testing.T) {
	a := Analyze(trust(`,"Condition":{
       "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
       "ForAnyValue:StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`))
	if sev := kinds(a)[SubjectSpansRepositories]; sev != "high" {
		t.Fatalf("a wildcard under a set-operator prefix is still a wildcard; got %q", sev)
	}
}

func TestAnalyze_WeaknessCarriesObservedTextAndAFix(t *testing.T) {
	a := Analyze(trust(`,"Condition":{
       "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
       "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/api:*"}}`))
	for _, w := range a.Weaknesses {
		if w.Fix == "" {
			t.Errorf("%s has no fix — a finding a customer cannot act on is half a finding", w.Kind)
		}
	}
	var found bool
	for _, w := range a.Weaknesses {
		if w.Kind == SubjectSpansRefs && strings.Contains(w.Observed, "repo:acme/api:*") {
			found = true
		}
	}
	if !found {
		t.Fatal("the finding must quote the condition it read, so a reader can check it")
	}
}
