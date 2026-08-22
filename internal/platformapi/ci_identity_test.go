package platformapi

import (
	"strings"
	"testing"
)

// The whole point of this wiring: a trust policy that lets ANY repository assume an admin role must
// produce a finding. Before it, ghoidc.Assess had no caller outside its own tests, so this finding
// existed only in a package nothing ran.
func TestCIIdentityFindings_UnpinnedAdminRoleIsFound(t *testing.T) {
	body := []byte(`{"account_id":"123456789012","roles":[{
      "arn":"arn:aws:iam::123456789012:role/Deploy","name":"Deploy","admin":true,
      "trust_policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"}}]}"}]}`)

	got := ciIdentityFindings("aws", body)
	if len(got) == 0 {
		t.Fatal("an admin role assumable by any GitHub repository produced no finding")
	}
	var joined string
	for _, f := range got {
		joined += f.Title + " " + f.Description + " " + f.Endpoint + " "
	}
	if !strings.Contains(joined, "role/Deploy") {
		t.Errorf("the finding must name the role it is about: %q", joined)
	}
}

// Privileged must come from the collector's Admin flag, not be assumed. It escalates a finding one
// step and says why, so hardcoding it would put a raised severity on every customer's non-admin role.
//
// The base weakness here is an OWNER-scoped sub ("repo:acme/*" — high), deliberately not an absent
// sub: that is already critical and escalate() is capped there, so the escalation would be invisible
// and the test would fail while the wiring was correct. My first version made exactly that mistake.
func TestCIIdentityFindings_PrivilegedComesFromTheCollector(t *testing.T) {
	tp := `"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Principal\":{\"Federated\":\"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com\"},\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/*\"}}}]}"`
	admin := ciIdentityFindings("aws", []byte(`{"account_id":"1","roles":[{"arn":"arn:aws:iam::1:role/A","name":"A","admin":true,"trust_policy":`+tp+`}]}`))
	plain := ciIdentityFindings("aws", []byte(`{"account_id":"1","roles":[{"arn":"arn:aws:iam::1:role/B","name":"B","trust_policy":`+tp+`}]}`))
	if len(admin) == 0 || len(plain) == 0 {
		t.Fatalf("both owner-scoped trusts must be findings (admin=%d plain=%d)", len(admin), len(plain))
	}
	if admin[0].Severity == plain[0].Severity {
		t.Errorf("the admin flag must change the assessment; both came back %q — Privileged is not "+
			"reaching ghoidc from the collector", admin[0].Severity)
	}
}

// A correctly pinned trust is not a finding. Without this the wiring could "work" by alarming on
// every federated role, which is the FP mode that makes a real one unreadable.
func TestCIIdentityFindings_PinnedTrustIsClean(t *testing.T) {
	body := []byte(`{"account_id":"123456789012","roles":[{
      "arn":"arn:aws:iam::123456789012:role/Deploy","name":"Deploy",
      "trust_policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"},\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/api:ref:refs/heads/main\"}}}}]}"}]}`)

	if got := ciIdentityFindings("aws", body); len(got) != 0 {
		t.Errorf("a trust pinned to one repository and ref is not a weakness: %+v", got)
	}
}

// A role with no trust policy is skipped, never assumed open.
func TestCIIdentityFindings_NoTrustPolicyIsNotAssumedOpen(t *testing.T) {
	body := []byte(`{"account_id":"1","roles":[{"arn":"arn:aws:iam::1:role/R","name":"R","admin":true}]}`)
	if got := ciIdentityFindings("aws", body); len(got) != 0 {
		t.Errorf("an unobserved trust policy must not produce a finding: %+v", got)
	}
}

// GCP is deliberately NOT half-wired. RawGCP carries no pool or provider objects, so running gcpwif
// over it would return a confident zero — the clean-because-we-did-not-look answer this codebase
// keeps having to fix.
func TestCIIdentityFindings_GCPNotClaimed(t *testing.T) {
	if got := ciIdentityFindings("gcp", []byte(`{"project_id":"p"}`)); got != nil {
		t.Errorf("GCP must not be assessed until its ingest carries WIF data: %+v", got)
	}
}
