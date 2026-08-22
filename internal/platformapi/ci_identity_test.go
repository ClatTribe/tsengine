package platformapi

import (
	"context"
	"fmt"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
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

// THE JOIN, end to end: an unconditioned pool provider AND a pool-wide impersonation binding.
//
// Neither half looks wrong alone — an unconditioned provider reads as "fine, the bindings are
// narrow", a pool-wide binding as "fine, the provider is conditioned". Together, every GitHub
// repository on the internet can impersonate the service account. A scanner reading one object at a
// time cannot see it, which is why gcpwif exists and why RawGCP had to be able to express it.
func TestGCPCIIdentityFindings_OpenImpersonationIsFound(t *testing.T) {
	body := []byte(`{"project_id":"p","wif_providers":[{
      "project_number":"1234567890","pool_id":"ci-pool","id":"github",
      "issuer_uri":"https://token.actions.githubusercontent.com"}],
      "service_accounts":[{"email":"deploy@p.iam.gserviceaccount.com","admin":true,"bindings":[{
        "role":"roles/iam.serviceAccountTokenCreator",
        "members":["principalSet://iam.googleapis.com/projects/1234567890/locations/global/workloadIdentityPools/ci-pool/*"]}]}]}`)

	got := gcpCIIdentityFindings(body)
	if len(got) == 0 {
		t.Fatal("an unconditioned pool with a pool-wide impersonation binding produced no finding")
	}
	var joined string
	for _, f := range got {
		joined += f.RuleID + " " + f.Title + " " + f.Description + " "
	}
	if !strings.Contains(joined, "deploy@p.iam.gserviceaccount.com") {
		t.Errorf("the finding must name the service account at risk: %q", joined)
	}
}

// An inventory with no WIF providers yields nothing — the collector reporting none and the estate
// having none are the same fact here, and inventing a finding from absence is the opposite error.
func TestGCPCIIdentityFindings_NoProvidersIsSilent(t *testing.T) {
	if got := gcpCIIdentityFindings([]byte(`{"project_id":"p"}`)); len(got) != 0 {
		t.Errorf("an estate with no federation produced findings: %+v", got)
	}
}

// Privileged must come from the collector's admin flag rather than being assumed.
//
// For the JOIN finding it changes the DESCRIPTION rather than the severity, and that is correct:
// "any repository on the internet can impersonate this account" is already critical, so escalating
// past it would say nothing. What the flag adds is that the path ends in a project takeover — which
// is what a responder needs to know and what a wrong guess would fabricate.
//
// My first version of this test compared got[0].Severity, which is a different finding altogether
// (the unconditioned-provider one, which does not depend on the flag). It failed against correct
// code.
func TestGCPCIIdentityFindings_PrivilegedComesFromTheCollector(t *testing.T) {
	tmpl := `{"project_id":"p","wif_providers":[{"project_number":"1","pool_id":"pool","id":"gh",
      "issuer_uri":"https://token.actions.githubusercontent.com"}],
      "service_accounts":[{"email":"sa@p.iam.gserviceaccount.com","admin":%s,"bindings":[{
        "role":"roles/iam.serviceAccountTokenCreator",
        "members":["principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/*"]}]}]}`

	joinDesc := func(raw string) string {
		for _, f := range gcpCIIdentityFindings([]byte(raw)) {
			if strings.Contains(f.RuleID, "open_impersonation") {
				return f.Description
			}
		}
		t.Fatalf("the join finding did not fire: %s", raw)
		return ""
	}
	admin := joinDesc(fmt.Sprintf(tmpl, "true"))
	plain := joinDesc(fmt.Sprintf(tmpl, "false"))

	if !strings.Contains(admin, "administrative permissions") {
		t.Errorf("an admin service account should be described as a project takeover: %q", admin)
	}
	if strings.Contains(plain, "administrative permissions") {
		t.Errorf("a non-admin account was described as holding admin — the flag is being assumed, "+
			"not read from the collector: %q", plain)
	}
}

// The DISPATCH must route gcp to the GCP assessor.
//
// The tests above call gcpCIIdentityFindings directly, so they pass even if ciIdentityFindings never
// routes to it — which is the "built but not wired" gap in miniature, inside the test suite meant to
// prove wiring. Found by mutation: unwiring the switch arm failed nothing.
func TestCIIdentityFindings_RoutesGCPToTheGCPAssessor(t *testing.T) {
	body := []byte(`{"project_id":"p","wif_providers":[{
      "project_number":"1","pool_id":"pool","id":"gh",
      "issuer_uri":"https://token.actions.githubusercontent.com"}],
      "service_accounts":[{"email":"sa@p.iam.gserviceaccount.com","bindings":[{
        "role":"roles/iam.serviceAccountTokenCreator",
        "members":["principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/*"]}]}]}`)

	got := ciIdentityFindings("gcp", body)
	if len(got) == 0 {
		t.Fatal("provider=gcp produced no findings — the dispatch does not reach the GCP assessor")
	}
	for _, f := range got {
		if !strings.HasPrefix(f.RuleID, "gcpwif::") {
			t.Errorf("unexpected rule from the gcp arm: %q", f.RuleID)
		}
	}
}

// And an unmodelled provider still yields nothing rather than being run through the wrong assessor.
func TestCIIdentityFindings_UnmodelledProviderIsSilent(t *testing.T) {
	if got := ciIdentityFindings("azure", []byte(`{"subscription_id":"s"}`)); got != nil {
		t.Errorf("azure has no analyser and must not be assessed by another cloud's: %+v", got)
	}
}

// The DECLARATIONS must survive the ingest, not just the findings.
//
// ghoidc refuses to judge a federation whose issuer it does not model — an Okta or other SAML
// provider — and says so instead of staying silent. The platform wiring took only .Findings, so that
// honest half stayed in the package: an estate federating through Okta reached the platform looking
// exactly like one that federates through nothing.
func TestCIIdentityAssess_CarriesTheUnassessedFederation(t *testing.T) {
	body := []byte(`{"account_id":"123456789012","roles":[{
      "arn":"arn:aws:iam::123456789012:role/OktaAdmin","name":"OktaAdmin","admin":true,
      "trust_policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithSAML\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:saml-provider/Okta\"}}]}"}]}`)

	findings, notAssessed := ciIdentityAssess("aws", body)
	// A samltrust finding is EXPECTED now — the audience is unconstrained — and that is the point of
	// the assertion below: assessing the one decidable case must not silence the declaration about
	// everything else the SAML grammar can express. What must NOT appear is a ghoidc verdict, which
	// would mean the GitHub analyser had judged a SAML trust it does not model.
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "ghoidc::") {
			t.Errorf("the GitHub analyser judged a SAML trust it does not model: %+v", f)
		}
	}
	if len(notAssessed) == 0 {
		t.Fatal("the Okta federation was dropped — the estate now reads as though nothing federates in")
	}
	var joined string
	for _, v := range notAssessed {
		joined += v + " "
	}
	if !strings.Contains(joined, "saml-provider/Okta") {
		t.Errorf("the declaration must name the provider to be actionable: %q", joined)
	}
}

// A GCP pool federating an issuer gcpwif does not model declares the same way.
func TestCIIdentityAssess_GCPCarriesTheUnassessedIssuer(t *testing.T) {
	body := []byte(`{"project_id":"p","wif_providers":[{
      "project_number":"1","pool_id":"corp","id":"okta","issuer_uri":"https://acme.okta.com"}]}`)

	_, notAssessed := ciIdentityAssess("gcp", body)
	if len(notAssessed) == 0 {
		t.Fatal("a non-GitHub GCP issuer was dropped at the ingest")
	}
	var joined string
	for _, v := range notAssessed {
		joined += v + " "
	}
	if !strings.Contains(joined, "acme.okta.com") {
		t.Errorf("the declaration must name the issuer: %q", joined)
	}
}

// The Okta trust that was previously only DECLARED is now a FINDING where it is decidable.
//
// Tested at ciIdentityAssess — the entry point the ingest calls — because three ticks running,
// mutating the wiring caught tests that only exercised the assessor.
func TestCIIdentityAssess_SAMLUnconstrainedAudienceBecomesAFinding(t *testing.T) {
	body := []byte(`{"account_id":"123456789012","roles":[{
      "arn":"arn:aws:iam::123456789012:role/OktaAdmin","name":"OktaAdmin","admin":true,
      "trust_policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithSAML\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:saml-provider/Okta\"}}]}"}]}`)

	findings, notAssessed := ciIdentityAssess("aws", body)
	var samlFinding bool
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "samltrust::") {
			samlFinding = true
			if f.Severity != types.SeverityCritical {
				t.Errorf("an admin role open to any assertion audience should be critical, got %q", f.Severity)
			}
		}
	}
	if !samlFinding {
		t.Fatalf("the SAML trust produced no finding at the ingest: %+v", findings)
	}
	// The declaration stays too: we assessed the audience, not the whole federation.
	if len(notAssessed) == 0 {
		t.Error("assessing one decidable case must not silence the declaration about the rest")
	}
}

// A properly constrained SAML trust yields no finding, so the check is not simply alarming on every
// federated role.
func TestCIIdentityAssess_ConstrainedSAMLTrustIsClean(t *testing.T) {
	body := []byte(`{"account_id":"1","roles":[{
      "arn":"arn:aws:iam::1:role/Okta","name":"Okta","admin":true,
      "trust_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithSAML\",\"Principal\":{\"Federated\":\"arn:aws:iam::1:saml-provider/Okta\"},\"Condition\":{\"StringEquals\":{\"SAML:aud\":\"https://signin.aws.amazon.com/saml\"}}}]}"}]}`)

	findings, _ := ciIdentityAssess("aws", body)
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "samltrust::") {
			t.Errorf("a constrained trust was reported: %+v", f)
		}
	}
}

// A federated-trust finding must NOT be recorded as drift.
//
// It reused the drift persister, so the ledger read "cloud drift detected" with a drift_findings
// count. A role trusting an unconstrained SAML provider is not drift: nothing changed, the policy has
// most likely been that way since it was written. The ledger is where a claim is supposed to be
// checkable, so "we detected drift" — a claim about an event that did not happen — is worse there
// than anywhere else.
func TestPersistCIIdentityFindings_IsNotRecordedAsDrift(t *testing.T) {
	rec := ledger.NewRecorder()
	d := Deps{Store: store.NewMemory(), Recorder: rec, NewID: func() string { return "1" }}

	saved, n := d.persistCIIdentityFindings(context.Background(), "t1", []types.Finding{{
		RuleID: "samltrust::saml_trust_audience_unconstrained", Tool: "samltrust",
		Severity: types.SeverityHigh, Endpoint: "arn:aws:iam::1:role/R", Title: "unconstrained audience",
	}})
	if n != 1 || len(saved) != 1 {
		t.Fatalf("the finding was not stored: n=%d saved=%d", n, len(saved))
	}

	var kinds, whats string
	for _, st := range rec.Steps() {
		kinds += st.Tool + " "
		whats += st.Thought + " " + st.Observation + " "
	}
	if strings.Contains(strings.ToLower(kinds+whats), "drift") {
		t.Errorf("a federated-trust finding was recorded as drift: kinds=%q what=%q", kinds, whats)
	}
	if !strings.Contains(kinds, "ci_identity") {
		t.Errorf("the assessment was not recorded under its own kind: %q", kinds)
	}
	// And the id says what produced it, rather than attributing it to a drift run.
	if strings.HasPrefix(saved[0].ID, "drift") {
		t.Errorf("the finding id attributes it to drift: %q", saved[0].ID)
	}
}
