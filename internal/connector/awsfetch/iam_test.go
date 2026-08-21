package awsfetch

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The identity layer is what makes an inventory capable of showing an attack path at all: cloudgraph
// builds paths out of principals and the trust edges between them. Buckets alone form no chain.

type fakeIAM struct {
	out []Principal
	err error
}

func (f fakeIAM) ListPrincipals(context.Context) ([]Principal, error) { return f.out, f.err }

func TestFetch_PrincipalsAndTrustReachTheInventory(t *testing.T) {
	res, err := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "data"}}},
		Principals: fakeIAM{out: []Principal{
			{ARN: "arn:aws:iam::1234:user/ana", Name: "ana"},
			{ARN: "arn:aws:iam::1234:role/deploy", Name: "deploy", Role: true, Admin: true,
				Trust: `{"Statement":[{"Principal":{"AWS":"arn:aws:iam::999:root"}}]}`},
		}},
	}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Raw.Users) != 1 || len(res.Raw.Roles) != 1 {
		t.Fatalf("users=%d roles=%d, want 1 and 1", len(res.Raw.Users), len(res.Raw.Roles))
	}
	if !res.Raw.Roles[0].Admin {
		t.Error("an admin role lost its Privileged flag — the graph would not treat it as a crown jewel")
	}
	// The trust policy is what becomes a trust EDGE. Losing it loses the path.
	if !strings.Contains(res.Raw.Roles[0].TrustPolicyJSON, "999:root") {
		t.Errorf("the trust policy did not survive into the inventory: %q", res.Raw.Roles[0].TrustPolicyJSON)
	}
	if !res.Covers("iam") {
		t.Error("iam was read but not reported as covered")
	}
}

// With IAM read, the coverage line must stop claiming it is unread — otherwise it under-reports and
// the customer is told to worry about a gap that no longer exists.
func TestCoverage_StopsNamingIAMOnceItIsRead(t *testing.T) {
	res, _ := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "b"}}},
		// Policies present, so this represents a COMPLETE identity read — otherwise the
		// fetcher rightly names iam-policies as unread and the assertion below (which
		// substring-matches "iam") would trip on a surface it was not written about.
		Principals: fakeIAM{out: []Principal{{ARN: "a", Name: "a",
			Policies: []string{`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`}}}},
	}.Fetch(context.Background())

	cov := res.Coverage()
	if !strings.Contains(cov, "iam") && !strings.Contains(cov, "s3") {
		t.Errorf("coverage names neither surface it read: %q", cov)
	}
	if strings.Contains(cov, "NOT read: ec2, iam") {
		t.Errorf("coverage still lists iam as unread after reading it: %q", cov)
	}
	// ec2 is still genuinely unread and must still be named.
	if !strings.Contains(cov, "ec2") {
		t.Errorf("coverage stopped naming ec2, which is still unread: %q", cov)
	}
}

// An IAM failure must be recorded, not swallowed — and must not fail the whole fetch when another
// surface succeeded, because a partial answer that says so is still useful.
func TestFetch_IAMFailureIsRecordedButS3StillCounts(t *testing.T) {
	res, err := Fetcher{
		AccountID:  "1234",
		Buckets:    fakeLister{out: []Bucket{{Name: "b"}}},
		Principals: fakeIAM{err: errors.New("AccessDenied: iam:ListUsers")},
	}.Fetch(context.Background())
	if err != nil {
		t.Fatalf("a fetch with one good surface failed entirely: %v", err)
	}
	if !res.Covers("s3") {
		t.Error("s3 succeeded but is not covered")
	}
	if res.Covers("iam") {
		t.Error("iam failed but is reported as covered")
	}
	if !strings.Contains(res.Skipped["iam"], "AccessDenied") {
		t.Errorf("the IAM failure lost its cause: %q", res.Skipped["iam"])
	}
}

// AWS URL-ENCODES the trust policy. Parsing it raw finds no principals — and a graph with no trust
// edges shows no attack paths, which reads as a clean account.
func TestDecodeTrustPolicy_HandlesAWSURLEncoding(t *testing.T) {
	raw := `{"Statement":[{"Principal":{"AWS":"arn:aws:iam::999:root"}}]}`
	encoded := url.QueryEscape(raw)

	got := decodeTrustPolicy(encoded)
	if !strings.Contains(got, "999:root") {
		t.Fatalf("an AWS-encoded trust policy did not decode: %q", got)
	}
	if trustPrincipalCount(got) != 1 {
		t.Error("the decoded policy does not parse as JSON — trust edges would be silently lost")
	}
	// An already-decoded document must pass through untouched, not be double-decoded.
	if trustPrincipalCount(decodeTrustPolicy(raw)) != 1 {
		t.Error("an already-decoded policy was mangled")
	}
	if decodeTrustPolicy("") != "" {
		t.Error("an empty policy produced content")
	}
}

// Admin comes from POLICY, never from the name — a user called "admin" with no policies is not one,
// and "ci-deploy" with AdministratorAccess is.
func TestAnyAdminPolicy_JudgesByPolicyNotName(t *testing.T) {
	if anyAdminPolicy(attached("arn:aws:iam::aws:policy/ReadOnlyAccess")) {
		t.Error("ReadOnlyAccess was treated as admin")
	}
	if !anyAdminPolicy(attached("arn:aws:iam::aws:policy/AdministratorAccess")) {
		t.Error("AdministratorAccess was not recognised")
	}
	if anyAdminPolicy(nil) {
		t.Error("a principal with no attached policies was marked admin")
	}
	// A customer-managed policy NAMED like admin proves nothing without its document.
	if anyAdminPolicy(attached("arn:aws:iam::1234:policy/SuperAdminLike")) {
		t.Error("a policy was judged admin by its name — the document is the fact, the name is a convention")
	}
}

// attached builds AttachedPolicy slices for the admin table above.
func attached(arns ...string) []iamtypes.AttachedPolicy {
	out := make([]iamtypes.AttachedPolicy, 0, len(arns))
	for _, a := range arns {
		out = append(out, iamtypes.AttachedPolicy{PolicyArn: aws.String(a)})
	}
	return out
}
