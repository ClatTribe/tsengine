package auditreview

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func reviewed(t *testing.T, fs []types.Finding, ds ...Disposition) Review {
	t.Helper()
	return Build("https://app.example", "OWASP Top 10 (2021)", fs, key, ds)
}

func include(t *testing.T, k string) Disposition {
	t.Helper()
	d, err := Decide("t1", "https://app.example", k, VerdictInclude, "", "", "Ada Auditor", now)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func blockerKinds(bs []Blocker) string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.Kind
	}
	return strings.Join(out, ",")
}

// THE CENTRAL REFUSAL. This certificate is what lets a government buyer host on NIC infrastructure;
// a third party relies on it and cannot see what it rested on. Issuing one over findings nobody
// reviewed would be the product's worst possible output.
func TestCertify_RefusesWhileAnythingIsUndecided(t *testing.T) {
	fs := []types.Finding{
		finding("f1", "nuclei::weak-tls", "low"),
		finding("f2", "nuclei::xss-reflected", "high"),
	}
	r := reviewed(t, fs, include(t, "nuclei::weak-tls|https://app.example/x"))

	cert, blockers := Certify(r, CertifyOptions{Auditor: "Ada Auditor"}, now)
	if cert != nil {
		t.Fatal("a certificate was issued with a finding nobody had reviewed")
	}
	if !strings.Contains(blockerKinds(blockers), "undecided") {
		t.Errorf("blockers = %s", blockerKinds(blockers))
	}
}

// An audit that examined nothing certifies nothing. Zero findings and zero decisions would otherwise
// satisfy every other check and read as a completed clean audit.
func TestCertify_RefusesAnEmptyScope(t *testing.T) {
	_, blockers := Certify(reviewed(t, nil), CertifyOptions{Auditor: "Ada Auditor"}, now)
	if !strings.Contains(blockerKinds(blockers), "empty_scope") {
		t.Fatalf("an empty audit was not refused: %s", blockerKinds(blockers))
	}
}

// A certificate with no name on it is not an attestation.
func TestCertify_RefusesWithoutANamedAuditor(t *testing.T) {
	r := reviewed(t, []types.Finding{finding("f1", "nuclei::weak-tls", "low")},
		include(t, "nuclei::weak-tls|https://app.example/x"))
	_, blockers := Certify(r, CertifyOptions{}, now)
	if !strings.Contains(blockerKinds(blockers), "no_auditor") {
		t.Fatalf("issued without an auditor: %s", blockerKinds(blockers))
	}
}

// The tender flow is draft → remediate → re-test → final → certificate. A serious finding still open
// at issue time means the loop did not complete, and the certificate must not paper over it.
func TestCertify_RefusesWhileSeriousFindingsAreOpenAndAcceptsOnceRetested(t *testing.T) {
	fs := []types.Finding{finding("f1", "webagent::sqli", "critical", exploited)}
	k := "webagent::sqli|https://app.example/x"
	r := reviewed(t, fs, include(t, k))

	_, blockers := Certify(r, CertifyOptions{Auditor: "Ada Auditor"}, now)
	if !strings.Contains(blockerKinds(blockers), "unresolved") {
		t.Fatalf("an open critical did not block issue: %s", blockerKinds(blockers))
	}

	cert, blockers := Certify(r, CertifyOptions{
		Auditor: "Ada Auditor", Resolved: map[string]bool{k: true},
	}, now)
	if cert == nil {
		t.Fatalf("a re-tested finding still blocked issue: %s", blockerKinds(blockers))
	}
	if !strings.Contains(cert.Statement, "No findings remain open at or above critical") {
		t.Errorf("statement: %q", cert.Statement)
	}
}

// EXCLUSIONS ARE STATED. A reader is entitled to know the reviewer exercised judgement and how
// often; a certificate that mentions only what was included reads as though nothing was set aside.
func TestCertificate_StatesExclusionsAndUntestedScope(t *testing.T) {
	fs := []types.Finding{
		finding("f1", "nuclei::weak-tls", "low"),
		finding("f2", "nuclei::banner", "info"),
	}
	inc := include(t, "nuclei::weak-tls|https://app.example/x")
	exc, err := Decide("t1", "https://app.example", "nuclei::banner|https://app.example/x",
		VerdictExclude, "", "informational banner, not in scope for this audit", "Ada Auditor", now)
	if err != nil {
		t.Fatal(err)
	}
	r := reviewed(t, fs, inc, exc)

	cert, blockers := Certify(r, CertifyOptions{
		Auditor: "Ada Auditor", Firm: "Acme Audit LLP", Standard: "OWASP Top 10 (2021)",
		NotTested: []string{"authenticated user roles (no credentials supplied)", "the mobile client"},
	}, now)
	if cert == nil {
		t.Fatalf("blocked: %s", blockerKinds(blockers))
	}
	if !strings.Contains(cert.Statement, "excluded with reasons recorded") {
		t.Errorf("the statement hides that a finding was excluded: %q", cert.Statement)
	}
	if !strings.Contains(cert.Statement, "Not covered by this assessment") ||
		!strings.Contains(cert.Statement, "the mobile client") {
		t.Errorf("untested scope is not on the certificate: %q", cert.Statement)
	}
	// The limit that stops a certificate being read as a guarantee.
	if !strings.Contains(cert.Statement, "not a guarantee") {
		t.Errorf("the certificate reads as a guarantee of security: %q", cert.Statement)
	}
	if cert.Excluded != 1 || cert.Included != 1 {
		t.Errorf("counts wrong: included=%d excluded=%d", cert.Included, cert.Excluded)
	}
}

// Every blocker at once, because a reviewer fixing them one at a time and re-submitting is the slow
// loop this product exists to remove.
func TestCertify_ReturnsEveryBlockerNotJustTheFirst(t *testing.T) {
	fs := []types.Finding{finding("f1", "webagent::sqli", "critical", exploited)}
	_, blockers := Certify(reviewed(t, fs), CertifyOptions{}, now)
	kinds := blockerKinds(blockers)
	for _, want := range []string{"no_auditor", "undecided", "unresolved"} {
		if !strings.Contains(kinds, want) {
			t.Errorf("blocker %q missing from %s", want, kinds)
		}
	}
}

// An EXCLUDED finding is not part of what the certificate asserts, so it cannot block issue — but it
// is still counted and still stated.
func TestCertify_AnExcludedFindingDoesNotBlockIssue(t *testing.T) {
	fs := []types.Finding{finding("f1", "webagent::sqli", "critical", exploited)}
	exc, err := Decide("t1", "https://app.example", "webagent::sqli|https://app.example/x",
		VerdictExclude, "", "test fixture endpoint, removed before go-live", "Ada Auditor", now)
	if err != nil {
		t.Fatal(err)
	}
	cert, blockers := Certify(reviewed(t, fs, exc), CertifyOptions{Auditor: "Ada Auditor"}, now)
	if cert == nil {
		t.Fatalf("an excluded finding blocked issue: %s", blockerKinds(blockers))
	}
	if cert.Excluded != 1 {
		t.Errorf("the exclusion was not counted: %+v", cert)
	}
}
