package samltrust

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func role(trust string, admin bool) Estate {
	return Estate{Roles: []Role{{
		ARN: "arn:aws:iam::123456789012:role/OktaAdmin", Name: "OktaAdmin",
		TrustPolicy: trust, Privileged: admin,
	}}}
}

const okta = `arn:aws:iam::123456789012:saml-provider/Okta`

// THE FINDING: a SAML trust with no audience condition accepts an assertion minted for ANY service
// provider the IdP serves, not only AWS. Someone able to obtain an assertion for another application
// at the same IdP can present it here.
func TestAssess_UnconstrainedAudienceIsFound(t *testing.T) {
	got := Assess(role(`{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
	  "Principal":{"Federated":"`+okta+`"}}]}`, false), time.Now())

	if len(got.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got.Findings), got.Findings)
	}
	f := got.Findings[0]
	if !strings.Contains(f.Description, "SAML:aud") {
		t.Errorf("the finding must name the missing condition: %q", f.Description)
	}
	if !strings.Contains(f.ToolArgs["providers"], "saml-provider/Okta") {
		t.Errorf("the finding must name the provider: %+v", f.ToolArgs)
	}
	if f.ToolArgs["fix"] == "" {
		t.Error("a finding whose fix is one condition should carry it")
	}
}

// A PRESENT condition is not judged. Whether it names the right audience is the customer's intent,
// and asserting on it would be a guess wearing a finding's clothes — gcpwif's rule, same reasoning.
func TestAssess_PresentAudienceConditionIsNotJudged(t *testing.T) {
	got := Assess(role(`{"Version":"2012-10-17","Statement":[{
	  "Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
	  "Principal":{"Federated":"`+okta+`"},
	  "Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}`, false), time.Now())

	if len(got.Findings) != 0 {
		t.Errorf("a constrained trust is not a weakness we can assert: %+v", got.Findings)
	}
}

// Case-insensitively: IAM condition keys are not case-sensitive and real policies write saml:aud,
// SAML:aud and SAML:Aud. Treating a differently-cased key as absent would be a false positive
// against a correctly configured customer.
func TestAssess_AudienceKeyIsCaseInsensitive(t *testing.T) {
	for _, k := range []string{"saml:aud", "SAML:Aud", "Saml:AUD"} {
		got := Assess(role(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
		  "Principal":{"Federated":"`+okta+`"},
		  "Condition":{"StringEquals":{"`+k+`":"https://signin.aws.amazon.com/saml"}}}]}`, false), time.Now())
		if len(got.Findings) != 0 {
			t.Errorf("%q was treated as absent: %+v", k, got.Findings)
		}
	}
}

// A DENY is the policy refusing the provider. Reporting it would turn good hygiene into a warning.
func TestAssess_DenyIsNotAFinding(t *testing.T) {
	got := Assess(role(`{"Statement":[{"Effect":"Deny","Action":"sts:AssumeRoleWithSAML",
	  "Principal":{"Federated":"`+okta+`"}}]}`, false), time.Now())
	if len(got.Findings) != 0 {
		t.Errorf("a Deny was reported as a weakness: %+v", got.Findings)
	}
}

// A WEB-IDENTITY trust is ghoidc's, not ours. Both firing on one statement would report a single
// defect twice.
func TestAssess_WebIdentityTrustIsNotOurs(t *testing.T) {
	got := Assess(role(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity",
	  "Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}}]}`, false), time.Now())
	if len(got.Findings) != 0 {
		t.Errorf("an OIDC web-identity trust belongs to ghoidc: %+v", got.Findings)
	}
}

// Privileged escalates and SAYS SO — supplied from IAM, never inferred from the trust policy, which
// does not say what a role can do.
func TestAssess_PrivilegedEscalatesAndExplains(t *testing.T) {
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
	  "Principal":{"Federated":"` + okta + `"}}]}`
	admin := Assess(role(trust, true), time.Now()).Findings
	plain := Assess(role(trust, false), time.Now()).Findings
	if len(admin) != 1 || len(plain) != 1 {
		t.Fatalf("both should be findings: admin=%d plain=%d", len(admin), len(plain))
	}
	if admin[0].Severity != types.SeverityCritical || plain[0].Severity != types.SeverityHigh {
		t.Errorf("the admin flag must change severity: admin=%s plain=%s", admin[0].Severity, plain[0].Severity)
	}
	if !strings.Contains(admin[0].Description, "account takeover") {
		t.Errorf("the escalation must say why: %q", admin[0].Description)
	}
}

// An UNPARSEABLE policy is declared, never treated as clean.
func TestAssess_UnparseablePolicyIsDeclared(t *testing.T) {
	got := Assess(role(`{not json`, false), time.Now())
	if len(got.Findings) != 0 {
		t.Errorf("nothing can be asserted about a policy we could not read: %+v", got.Findings)
	}
	if len(got.ChecksNotRun) == 0 {
		t.Fatal("an unreadable trust policy must be declared, not silently skipped")
	}
}

// No trust policy observed → nothing claimed either way.
func TestAssess_NoTrustPolicyIsSilent(t *testing.T) {
	got := Assess(role("", true), time.Now())
	if len(got.Findings) != 0 || len(got.ChecksNotRun) != 0 {
		t.Errorf("an unobserved policy is not a finding and not a gap: %+v %+v", got.Findings, got.ChecksNotRun)
	}
}

// PER-STATEMENT, not per-role — the shape a real account actually has.
//
// A role typically trusts more than one provider, and the realistic failure is a legacy one left
// unconstrained beside a correctly configured one. Two ways to get this wrong: check only the first
// statement and miss it, or condemn the whole role and tell the customer their working configuration
// is broken. The finding must name the provider that is actually open.
func TestAssess_FlagsOnlyTheUnconstrainedStatement(t *testing.T) {
	trust := `{"Version":"2012-10-17","Statement":[
	  {"Sid":"Constrained","Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
	   "Principal":{"Federated":"arn:aws:iam::1:saml-provider/Okta"},
	   "Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}},
	  {"Sid":"Open","Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
	   "Principal":{"Federated":"arn:aws:iam::1:saml-provider/Legacy"}}]}`

	got := Assess(Estate{Roles: []Role{{ARN: "arn:aws:iam::1:role/R", TrustPolicy: trust}}}, time.Now())
	if len(got.Findings) != 1 {
		t.Fatalf("want exactly one finding — the open statement — got %d: %+v", len(got.Findings), got.Findings)
	}
	provs := got.Findings[0].ToolArgs["providers"]
	if !strings.Contains(provs, "saml-provider/Legacy") {
		t.Errorf("the finding must name the OPEN provider: %q", provs)
	}
	if strings.Contains(provs, "saml-provider/Okta") {
		t.Errorf("the correctly-configured provider was named as at fault: %q", provs)
	}
}

// SAML:sub IS DELIBERATELY NOT CHECKED, and this test exists to stop it being added.
//
// It looks like the obvious sibling of the audience check and it is not. In AWS SAML federation the
// IdP's role-attribute mapping decides which users may assume which role — so a trust that does not
// pin SAML:sub is the INTENDED design, not a weakness. Flagging it would fire on nearly every
// correctly configured account in existence.
//
// The distinction is what makes the audience check sound: an absent SAML:aud lets in an assertion
// minted for a DIFFERENT service provider, which the customer did not intend; an absent SAML:sub
// admits the users the customer's own IdP chose to send.
func TestAssess_AbsentSubjectConditionIsNotAWeakness(t *testing.T) {
	got := Assess(role(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithSAML",
	  "Principal":{"Federated":"`+okta+`"},
	  "Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}`, true), time.Now())

	if len(got.Findings) != 0 {
		t.Errorf("a trust with a pinned audience and no subject condition is the normal, intended "+
			"design — reporting it would fire on nearly every correct account: %+v", got.Findings)
	}
}
