package cloudiam

import (
	"encoding/json"
	"testing"
)

// A GitHub Actions OIDC trust policy. The Federated principal is the OIDC provider
// ARN; the sub/aud Conditions are what actually bound who may assume the role.
const ghTrust = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
      "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main"}
    }
  }]
}`

func TestPrincipalMatches_FederatedProviderIsRecognised(t *testing.T) {
	var d Document
	if err := json.Unmarshal([]byte(ghTrust), &d); err != nil {
		t.Fatal(err)
	}
	prov := "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
	matched, present := principalMatches(d.Statement[0].Principal, prov)
	if !present {
		t.Fatal("Principal element should be present on a trust policy")
	}
	if !matched {
		t.Fatal("the GitHub OIDC provider ARN must match its own Federated principal — " +
			"without this every CI-to-cloud trust is invisible to the evaluator")
	}
}

func TestPrincipalMatches_DifferentFederatedProviderDoesNotMatch(t *testing.T) {
	var d Document
	if err := json.Unmarshal([]byte(ghTrust), &d); err != nil {
		t.Fatal(err)
	}
	// A GitLab OIDC provider must not match a GitHub-trusting policy.
	other := "arn:aws:iam::123456789012:oidc-provider/gitlab.com"
	if matched, _ := principalMatches(d.Statement[0].Principal, other); matched {
		t.Fatal("a different identity provider must not satisfy this trust")
	}
}

// The mutation that matters: Federated must not leak into the AWS principal path.
// An AWS principal ARN must NOT be satisfied by a Federated-only trust, or every
// cross-account question would answer yes on a CI trust policy.
func TestPrincipalMatches_AWSPrincipalIsNotSatisfiedByFederatedOnlyTrust(t *testing.T) {
	var d Document
	if err := json.Unmarshal([]byte(ghTrust), &d); err != nil {
		t.Fatal(err)
	}
	if matched, _ := principalMatches(d.Statement[0].Principal, "arn:aws:iam::999:role/attacker"); matched {
		t.Fatal("an IAM role must not match a Federated-only trust policy")
	}
}

// Authorize must still require the CONDITION to hold. A Federated match alone is
// config-possible, never sufficient — the whole point of the OIDC work.
func TestAuthorize_FederatedTrustIsConditionGatedNotAutomaticAllow(t *testing.T) {
	d, err := Parse([]byte(ghTrust))
	if err != nil {
		t.Fatal(err)
	}
	prov := "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"

	// The RIGHT workflow context (repo acme/api on main) satisfies the conditions.
	ok := Request{
		Principal: prov, Action: "sts:AssumeRoleWithWebIdentity",
		Resource: "arn:aws:iam::123456789012:role/deploy",
		Context: map[string]string{
			"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
			"token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main",
		},
	}
	if dec, _ := Authorize(ok, PolicySet{ResourcePolicy: d, SameAccount: true}); dec != Allow {
		t.Fatalf("the trusted workflow context should be allowed, got %v", dec)
	}

	// A DIFFERENT repo presents a sub the condition does not match → not allowed.
	bad := ok
	bad.Context = map[string]string{
		"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
		"token.actions.githubusercontent.com:sub": "repo:attacker/evil:ref:refs/heads/main",
	}
	if dec, _ := Authorize(bad, PolicySet{ResourcePolicy: d, SameAccount: true}); dec == Allow {
		t.Fatal("an untrusted repository must NOT be allowed — the Federated match is " +
			"config-possible, and only the sub condition decides")
	}
}
