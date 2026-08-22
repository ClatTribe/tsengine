package ghoidc

import (
	"strings"
	"testing"
	"time"
)

// A role an Okta/SAML provider can assume is a real identity transition into the cloud account. This
// analyser does not evaluate those — the claim grammar differs per provider — but it must not stay
// SILENT about them, because a skipped check and a clean result are different facts and only one of
// them is true here.
func TestAssess_DeclaresUnassessedFederation(t *testing.T) {
	const oktaTrust = `{"Version":"2012-10-17","Statement":[{
      "Effect":"Allow",
      "Action":"sts:AssumeRoleWithSAML",
      "Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/Okta"},
      "Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}`

	got := Assess(Estate{Roles: []Role{{ARN: "arn:aws:iam::123456789012:role/OktaAdmin", TrustPolicy: oktaTrust}}}, time.Now())

	if len(got.Findings) != 0 {
		t.Fatalf("must not invent a finding for a provider it does not evaluate: %+v", got.Findings)
	}
	note, ok := got.ChecksNotRun["federated_trust:arn:aws:iam::123456789012:role/OktaAdmin"]
	if !ok {
		t.Fatal("an Okta SAML federation was dropped silently — the estate reads clean when a whole " +
			"workforce IdP can assume this role")
	}
	if !strings.Contains(note, "saml-provider/Okta") {
		t.Errorf("the declaration must NAME the provider so it is actionable: %q", note)
	}
}

// A GitHub trust must keep being assessed, not diverted into the declaration.
func TestAssess_GitHubStillAssessed(t *testing.T) {
	const ghTrust = `{"Version":"2012-10-17","Statement":[{
      "Effect":"Allow",
      "Action":"sts:AssumeRoleWithWebIdentity",
      "Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}}]}`

	got := Assess(Estate{Roles: []Role{{ARN: "arn:aws:iam::123456789012:role/CI", TrustPolicy: ghTrust}}}, time.Now())
	if len(got.Findings) == 0 {
		t.Fatal("an unpinned GitHub trust must still be a finding")
	}
	if _, declared := got.ChecksNotRun["federated_trust:arn:aws:iam::123456789012:role/CI"]; declared {
		t.Error("a GitHub provider must be ASSESSED, not declared unassessed")
	}
}

// A DENY naming a provider is the policy working. Reporting it as an unassessed trust would turn good
// hygiene into a warning.
func TestAssess_DenyIsNotAnUnassessedFederation(t *testing.T) {
	const denyTrust = `{"Version":"2012-10-17","Statement":[{
      "Effect":"Deny",
      "Action":"sts:AssumeRoleWithSAML",
      "Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/Okta"}}]}`

	got := Assess(Estate{Roles: []Role{{ARN: "arn:aws:iam::1:role/R", TrustPolicy: denyTrust}}}, time.Now())
	if _, declared := got.ChecksNotRun["federated_trust:arn:aws:iam::1:role/R"]; declared {
		t.Error("a Deny is the policy refusing the provider, not an unassessed trust")
	}
}
