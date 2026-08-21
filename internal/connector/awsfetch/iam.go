package awsfetch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// iam.go reads the identity layer — the surface that makes an inventory capable of showing an attack
// path at all.
//
// Buckets alone cannot form a chain. cloudgraph builds paths out of PRINCIPALS and the TRUST edges
// between them, so until this existed a live inventory could show a public bucket but never "this
// role can assume that role, which can read it". That is the whole product.
//
// # Two judgements this makes, and the reasoning behind each
//
// ADMIN IS RESOLVED FROM POLICY, NOT FROM THE NAME. A principal called "admin" may have nothing, and
// one called "ci-deploy" may have *:*. Naming is a convention; the policy is the fact. So Privileged
// comes from an attached or inline policy that actually grants admin-equivalent access.
//
// A PRINCIPAL WHOSE POLICIES CANNOT BE READ IS NOT MARKED PRIVILEGED. The read-only role may lack
// iam:ListAttachedUserPolicies even where it can ListUsers. Marking those admin would flood the graph
// with false crown jewels; marking them non-admin is the quieter error and is what the caller's
// coverage line is for. Neither is silently correct, which is why the failure is recorded.

// IAMReader is the identity surface. An interface so the fetch logic is testable without credentials.
type IAMReader interface {
	ListPrincipals(ctx context.Context) ([]Principal, error)
}

// Principal is one IAM identity as the reader resolved it.
type Principal struct {
	ARN   string
	Name  string
	Role  bool   // false = user
	Admin bool   // resolved from policy, never from the name
	Trust string // the role's verbatim trust policy JSON; empty for users
	// Policies are the principal's attached + inline policy DOCUMENTS, verbatim. They are
	// what makes "can this principal BECOME admin" answerable; Admin only answers "is it
	// already". A reader that leaves them empty produces an inventory with no escalation
	// edges, which Coverage must then say out loud.
	Policies []string
	// Boundary is the permission-boundary document. Empty means NONE — never "denies
	// everything", because an unread boundary treated as a deny would erase every
	// escalation in the account.
	Boundary string
}

// iamAPI is the slice of IAM this needs — read verbs only, so the customer grants the minimum and a
// mistake here cannot change their account.
type iamAPI interface {
	ListUsers(ctx context.Context, in *iam.ListUsersInput, opts ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListRoles(ctx context.Context, in *iam.ListRolesInput, opts ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedUserPolicies(ctx context.Context, in *iam.ListAttachedUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

// IAMLister reads principals through the assumed read-only role.
type IAMLister struct {
	Region     string
	RoleARN    string
	ExternalID string

	api iamAPI // injected in tests
}

// NewIAMLister builds the live reader. No I/O at construction.
func NewIAMLister(region, roleARN, externalID string) *IAMLister {
	return &IAMLister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

// ListPrincipals returns every user and role, with admin resolved from attached policies and each
// role's trust policy decoded.
//
// Pagination is followed to the end: a truncated identity layer would silently drop principals, and a
// missing principal is a missing attack path — the failure mode that looks like a clean account.
func (l *IAMLister) ListPrincipals(ctx context.Context) ([]Principal, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	var out []Principal

	var userMarker *string
	for {
		res, err := api.ListUsers(ctx, &iam.ListUsersInput{Marker: userMarker})
		if err != nil {
			return nil, fmt.Errorf("awsfetch: list users: %w", err)
		}
		for _, u := range res.Users {
			p := Principal{ARN: aws.ToString(u.Arn), Name: aws.ToString(u.UserName)}
			p.Admin = l.userIsAdmin(ctx, api, p.Name)
			out = append(out, p)
		}
		if !res.IsTruncated {
			break
		}
		userMarker = res.Marker
	}

	var roleMarker *string
	for {
		res, err := api.ListRoles(ctx, &iam.ListRolesInput{Marker: roleMarker})
		if err != nil {
			return nil, fmt.Errorf("awsfetch: list roles: %w", err)
		}
		for _, r := range res.Roles {
			p := Principal{
				ARN: aws.ToString(r.Arn), Name: aws.ToString(r.RoleName), Role: true,
				Trust: decodeTrustPolicy(aws.ToString(r.AssumeRolePolicyDocument)),
			}
			p.Admin = l.roleIsAdmin(ctx, api, p.Name)
			out = append(out, p)
		}
		if !res.IsTruncated {
			break
		}
		roleMarker = res.Marker
	}
	return out, nil
}

// decodeTrustPolicy returns the trust policy as JSON. AWS URL-encodes the document; a caller that
// tried to parse it raw would find no principals and quietly build a graph with no trust edges.
func decodeTrustPolicy(doc string) string {
	if doc == "" {
		return ""
	}
	if dec, err := url.QueryUnescape(doc); err == nil {
		return dec
	}
	return doc // already decoded, or undecodable — hand it on rather than drop it
}

func (l *IAMLister) userIsAdmin(ctx context.Context, api iamAPI, name string) bool {
	if name == "" {
		return false
	}
	res, err := api.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(name)})
	if err != nil {
		return false // unreadable ≠ admin; see the file comment
	}
	return anyAdminPolicy(res.AttachedPolicies)
}

func (l *IAMLister) roleIsAdmin(ctx context.Context, api iamAPI, name string) bool {
	if name == "" {
		return false
	}
	res, err := api.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)})
	if err != nil {
		return false
	}
	return anyAdminPolicy(res.AttachedPolicies)
}

// anyAdminPolicy recognises admin-equivalent managed policies by ARN.
//
// Deliberately narrow: AdministratorAccess is unambiguous, and so is the account-root-equivalent
// PowerUserAccess-plus-IAM shape, but inferring "admin" from an arbitrary customer-managed policy
// needs the policy DOCUMENT, not its name — a policy called "ReadOnlyIsh" can grant *:*. Fetching and
// evaluating documents is the next increment; until then this matches what it can prove and leaves
// the rest unmarked rather than guessing from a name.
func anyAdminPolicy(ps []iamtypes.AttachedPolicy) bool {
	for _, p := range ps {
		arn := aws.ToString(p.PolicyArn)
		if strings.HasSuffix(arn, ":policy/AdministratorAccess") ||
			strings.HasSuffix(arn, ":policy/IAMFullAccess") {
			return true
		}
	}
	return false
}

// trustGrantsAnyone reports whether a decoded trust policy lets any principal assume the role — the
// wildcard that turns a role into an open door. Exported logic lives in cloudgraph; this is only used
// by the test that proves the document survives decoding intact.
func trustPrincipalCount(doc string) int {
	if strings.TrimSpace(doc) == "" {
		return 0
	}
	var pol struct {
		Statement []struct {
			Principal any `json:"Principal"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &pol) != nil {
		return 0
	}
	return len(pol.Statement)
}

// client builds the assumed-role IAM client on first use, or returns the injected test double.
func (l *IAMLister) client(ctx context.Context) (iamAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}
