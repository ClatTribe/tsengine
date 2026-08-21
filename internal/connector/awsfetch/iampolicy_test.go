package awsfetch

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeIAMAPI is the low-level IAM surface. Before this file nothing tested it at all —
// the existing fakes stub the high-level IAMReader, so every line of the live lister was
// unexercised.
type fakeIAMAPI struct {
	roles    []iamtypes.Role
	users    []iamtypes.User
	attached map[string][]string // principal name → attached policy ARNs
	docs     map[string]string   // policy ARN → document (already URL-encoded by AWS)
	inline   map[string][]string // principal name → inline policy names
	inlineDo map[string]string   // name+"/"+policy → document
	failDoc  map[string]bool     // policy ARN → GetPolicy fails

	getPolicyCalls int // proves the cache works
}

func (f *fakeIAMAPI) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: f.users}, nil
}
func (f *fakeIAMAPI) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}
func (f *fakeIAMAPI) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: attachedOf(f.attached[aws.ToString(in.UserName)])}, nil
}
func (f *fakeIAMAPI) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: attachedOf(f.attached[aws.ToString(in.RoleName)])}, nil
}
func (f *fakeIAMAPI) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	f.getPolicyCalls++
	arn := aws.ToString(in.PolicyArn)
	if f.failDoc[arn] {
		return nil, errors.New("access denied")
	}
	if _, ok := f.docs[arn]; !ok {
		return nil, errors.New("no such policy")
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")}}, nil
}
func (f *fakeIAMAPI) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		Document: aws.String(f.docs[aws.ToString(in.PolicyArn)]),
	}}, nil
}
func (f *fakeIAMAPI) ListRolePolicies(_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{PolicyNames: f.inline[aws.ToString(in.RoleName)]}, nil
}
func (f *fakeIAMAPI) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	k := aws.ToString(in.RoleName) + "/" + aws.ToString(in.PolicyName)
	return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(f.inlineDo[k])}, nil
}
func (f *fakeIAMAPI) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: f.inline[aws.ToString(in.UserName)]}, nil
}
func (f *fakeIAMAPI) GetUserPolicy(_ context.Context, in *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	k := aws.ToString(in.UserName) + "/" + aws.ToString(in.PolicyName)
	return &iam.GetUserPolicyOutput{PolicyDocument: aws.String(f.inlineDo[k])}, nil
}

func attachedOf(arns []string) []iamtypes.AttachedPolicy {
	out := make([]iamtypes.AttachedPolicy, 0, len(arns))
	for _, a := range arns {
		out = append(out, iamtypes.AttachedPolicy{PolicyArn: aws.String(a)})
	}
	return out
}

const escalatingDoc = `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`

func listWith(t *testing.T, f *fakeIAMAPI) []Principal {
	t.Helper()
	ps, err := (&IAMLister{api: f}).ListPrincipals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

// The capability itself: the DOCUMENT reaches the principal, URL-decoded. AWS returns it
// encoded, and parsed raw it yields no statements — a policy with no statements grants
// nothing, which is a silent under-read rather than a visible failure.
func TestListPrincipals_ReadsAndDecodesPolicyDocuments(t *testing.T) {
	f := &fakeIAMAPI{
		roles:    []iamtypes.Role{{Arn: aws.String("arn:aws:iam::1:role/app"), RoleName: aws.String("app")}},
		attached: map[string][]string{"app": {"arn:aws:iam::1:policy/deploy"}},
		docs:     map[string]string{"arn:aws:iam::1:policy/deploy": url.QueryEscape(escalatingDoc)},
	}
	ps := listWith(t, f)
	if len(ps) != 1 || len(ps[0].Policies) != 1 {
		t.Fatalf("want one role with one policy document, got %+v", ps)
	}
	if ps[0].Policies[0] != escalatingDoc {
		t.Fatalf("the document must be URL-decoded, got %q", ps[0].Policies[0])
	}
}

// THE CACHE IS NOT AN OPTIMISATION. Managed policies are shared by design; without it a
// hundred roles sharing one policy is two hundred calls, and an identity read slow enough
// to be switched off measures the same as one never built.
func TestListPrincipals_SharedManagedPolicyIsFetchedOnce(t *testing.T) {
	f := &fakeIAMAPI{
		roles: []iamtypes.Role{
			{Arn: aws.String("arn:aws:iam::1:role/a"), RoleName: aws.String("a")},
			{Arn: aws.String("arn:aws:iam::1:role/b"), RoleName: aws.String("b")},
			{Arn: aws.String("arn:aws:iam::1:role/c"), RoleName: aws.String("c")},
		},
		attached: map[string][]string{
			"a": {"arn:aws:iam::1:policy/shared"},
			"b": {"arn:aws:iam::1:policy/shared"},
			"c": {"arn:aws:iam::1:policy/shared"},
		},
		docs: map[string]string{"arn:aws:iam::1:policy/shared": escalatingDoc},
	}
	ps := listWith(t, f)
	if f.getPolicyCalls != 1 {
		t.Fatalf("one shared policy across three roles should be fetched once, got %d calls", f.getPolicyCalls)
	}
	for _, p := range ps {
		if len(p.Policies) != 1 {
			t.Fatalf("every role must still receive the document: %+v", p)
		}
	}
}

// One unreadable policy must not sink the principal it belongs to — failing the listing
// turns an access-denied into an account with no principals, which reads as a clean one.
func TestListPrincipals_UnreadablePolicyDoesNotSinkThePrincipal(t *testing.T) {
	f := &fakeIAMAPI{
		roles:    []iamtypes.Role{{Arn: aws.String("arn:aws:iam::1:role/app"), RoleName: aws.String("app")}},
		attached: map[string][]string{"app": {"arn:aws:iam::1:policy/denied", "arn:aws:iam::1:policy/ok"}},
		docs:     map[string]string{"arn:aws:iam::1:policy/ok": escalatingDoc},
		failDoc:  map[string]bool{"arn:aws:iam::1:policy/denied": true},
	}
	ps := listWith(t, f)
	if len(ps) != 1 {
		t.Fatalf("the role must survive an unreadable policy, got %+v", ps)
	}
	if len(ps[0].Policies) != 1 || ps[0].Policies[0] != escalatingDoc {
		t.Fatalf("the readable policy must still be kept: %+v", ps[0].Policies)
	}
	// And a failing ARN is retried once per pass, not once per principal.
	if f.getPolicyCalls != 2 {
		t.Fatalf("want 2 GetPolicy calls (one per distinct ARN), got %d", f.getPolicyCalls)
	}
}

// The permission boundary rides on the role listing — no extra call to discover it.
func TestListPrincipals_ResolvesThePermissionBoundary(t *testing.T) {
	bnd := `{"Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*"}]}`
	f := &fakeIAMAPI{
		roles: []iamtypes.Role{{
			Arn: aws.String("arn:aws:iam::1:role/app"), RoleName: aws.String("app"),
			PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
				PermissionsBoundaryArn: aws.String("arn:aws:iam::1:policy/bnd"),
			},
		}},
		attached: map[string][]string{"app": {"arn:aws:iam::1:policy/deploy"}},
		docs: map[string]string{
			"arn:aws:iam::1:policy/deploy": escalatingDoc,
			"arn:aws:iam::1:policy/bnd":    bnd,
		},
	}
	ps := listWith(t, f)
	if ps[0].Boundary != bnd {
		t.Fatalf("the boundary document must reach the principal, got %q", ps[0].Boundary)
	}
}

// A role with NO boundary must report none — not an empty one. awsinventory reads absent
// as unconstrained, and the distinction decides whether escalations survive.
func TestListPrincipals_NoBoundaryReportsNone(t *testing.T) {
	f := &fakeIAMAPI{
		roles:    []iamtypes.Role{{Arn: aws.String("arn:aws:iam::1:role/app"), RoleName: aws.String("app")}},
		attached: map[string][]string{"app": {"arn:aws:iam::1:policy/deploy"}},
		docs:     map[string]string{"arn:aws:iam::1:policy/deploy": escalatingDoc},
	}
	if b := listWith(t, f)[0].Boundary; b != "" {
		t.Fatalf("no boundary means empty, got %q", b)
	}
}

// Inline policies count too, and their order must be stable so the same account yields
// the same inventory twice running.
func TestListPrincipals_ReadsInlinePoliciesDeterministically(t *testing.T) {
	f := &fakeIAMAPI{
		roles:    []iamtypes.Role{{Arn: aws.String("arn:aws:iam::1:role/app"), RoleName: aws.String("app")}},
		attached: map[string][]string{},
		docs:     map[string]string{},
		inline:   map[string][]string{"app": {"zeta", "alpha"}}, // deliberately unsorted
		inlineDo: map[string]string{
			"app/alpha": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`,
			"app/zeta":  escalatingDoc,
		},
	}
	ps := listWith(t, f)
	if len(ps[0].Policies) != 2 {
		t.Fatalf("both inline policies must be read, got %+v", ps[0].Policies)
	}
	if !strings.Contains(ps[0].Policies[0], "s3:GetObject") {
		t.Fatalf("inline policies must be sorted for a stable inventory, got %+v", ps[0].Policies)
	}
}

// Admin stays a cheap ARN-name match, and must NOT be inferred from the documents — the
// two questions ("is it admin" / "can it become admin") are answered in different places
// on purpose.
func TestListPrincipals_AdminRemainsAnARNMatchNotADocumentInference(t *testing.T) {
	f := &fakeIAMAPI{
		roles: []iamtypes.Role{
			{Arn: aws.String("arn:aws:iam::1:role/admin"), RoleName: aws.String("admin")},
			{Arn: aws.String("arn:aws:iam::1:role/esc"), RoleName: aws.String("esc")},
		},
		attached: map[string][]string{
			"admin": {"arn:aws:iam::aws:policy/AdministratorAccess"},
			"esc":   {"arn:aws:iam::1:policy/deploy"},
		},
		docs: map[string]string{
			"arn:aws:iam::aws:policy/AdministratorAccess": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			"arn:aws:iam::1:policy/deploy":                escalatingDoc,
		},
	}
	byName := map[string]Principal{}
	for _, p := range listWith(t, f) {
		byName[p.Name] = p
	}
	if !byName["admin"].Admin {
		t.Error("AdministratorAccess is admin-equivalent by ARN")
	}
	if byName["esc"].Admin {
		t.Error("a role that can ESCALATE is not already an admin — that verdict belongs to awsinventory")
	}
}
