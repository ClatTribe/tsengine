package awsfetch

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// iampolicy.go reads the policy DOCUMENTS behind a principal, not just their names.
//
// ListPrincipals already called ListAttached*Policies — but only to match ARNs against a
// list of known admin-equivalent managed policies. That answers "is this principal
// already an admin" and can never answer "can this principal BECOME one", which is the
// attack path. The documents are what make the second question answerable.
//
// # Cost, and why the cache is not an optimisation
//
// Reading a document is GetPolicy (for the default version id) then GetPolicyVersion,
// per attached policy, per principal. In an account where two hundred roles share
// AWSLambdaBasicExecutionRole that is four hundred calls for one document. Managed
// policies are shared BY DESIGN, so caching by policy ARN is what makes this viable at
// all rather than a nicety — without it the identity read is slow enough that an operator
// turns it off, and a capability switched off measures the same as one never built.
//
// # Failure is per-document and never fatal
//
// A policy we cannot read is skipped and the rest are kept. The alternative — failing the
// whole listing — turns one unreadable policy into an account with no principals, which
// reads as a clean account. Under-reading is recoverable and states itself through
// Coverage; a fabricated clean bill of health is not.

// policyDocAPI is the additional IAM surface document reading needs. Read verbs only.
type policyDocAPI interface {
	GetPolicy(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, in *iam.GetRolePolicyInput, opts ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListUserPolicies(ctx context.Context, in *iam.ListUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(ctx context.Context, in *iam.GetUserPolicyInput, opts ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
}

// docCache memoises managed-policy documents by ARN for one listing pass. Not shared
// across passes: a policy edited between scans must be re-read, and a stale document
// would be worse than a slow one.
type docCache map[string]string

// managedDoc returns a managed policy's default-version document, cached by ARN.
// Returns "" when it cannot be read — never an error, because one unreadable policy must
// not sink the principal it belongs to.
func managedDoc(ctx context.Context, api policyDocAPI, cache docCache, arn string) string {
	if arn == "" {
		return ""
	}
	if doc, ok := cache[arn]; ok {
		return doc
	}
	cache[arn] = "" // negative-cache first, so a failing ARN is retried once per pass, not per principal

	pol, err := api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil || pol.Policy == nil {
		return ""
	}
	ver := aws.ToString(pol.Policy.DefaultVersionId)
	if ver == "" {
		return ""
	}
	pv, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(ver),
	})
	if err != nil || pv.PolicyVersion == nil {
		return ""
	}
	// Same URL-encoding as a trust policy: parsed raw it yields no statements, and a
	// policy with no statements grants nothing — a silent under-read.
	doc := decodeTrustPolicy(aws.ToString(pv.PolicyVersion.Document))
	cache[arn] = doc
	return doc
}

// rolePolicies returns a role's attached + inline policy documents.
func (l *IAMLister) rolePolicies(ctx context.Context, api policyDocAPI, attached []string, roleName string, cache docCache) []string {
	var out []string
	for _, arn := range attached {
		if doc := managedDoc(ctx, api, cache, arn); doc != "" {
			out = append(out, doc)
		}
	}
	if roleName == "" {
		return out
	}
	names, err := api.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return out // inline policies unreadable; the attached ones still stand
	}
	// Inline policy names are unordered from AWS; sort so the same account yields the
	// same inventory twice running.
	inline := append([]string(nil), names.PolicyNames...)
	sort.Strings(inline)
	for _, n := range inline {
		res, err := api.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName: aws.String(roleName), PolicyName: aws.String(n),
		})
		if err != nil || res.PolicyDocument == nil {
			continue
		}
		if doc := decodeTrustPolicy(aws.ToString(res.PolicyDocument)); doc != "" {
			out = append(out, doc)
		}
	}
	return out
}

// userPolicies is the user-side twin of rolePolicies.
func (l *IAMLister) userPolicies(ctx context.Context, api policyDocAPI, attached []string, userName string, cache docCache) []string {
	var out []string
	for _, arn := range attached {
		if doc := managedDoc(ctx, api, cache, arn); doc != "" {
			out = append(out, doc)
		}
	}
	if userName == "" {
		return out
	}
	names, err := api.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(userName)})
	if err != nil {
		return out
	}
	inline := append([]string(nil), names.PolicyNames...)
	sort.Strings(inline)
	for _, n := range inline {
		res, err := api.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
			UserName: aws.String(userName), PolicyName: aws.String(n),
		})
		if err != nil || res.PolicyDocument == nil {
			continue
		}
		if doc := decodeTrustPolicy(aws.ToString(res.PolicyDocument)); doc != "" {
			out = append(out, doc)
		}
	}
	return out
}

// boundaryDoc resolves a permission-boundary ARN to its document.
//
// An unreadable boundary returns "", which downstream means "this principal has no
// boundary" — deliberately, and it is the safe direction: awsinventory treats an absent
// boundary as unconstrained, so a boundary we failed to read can only make us report an
// escalation that a boundary might actually block. The opposite default would let one
// failed call silently erase every escalation in the account.
func boundaryDoc(ctx context.Context, api policyDocAPI, cache docCache, arn string) string {
	return managedDoc(ctx, api, cache, arn)
}

// attachedARNs pulls the policy ARNs off an attached-policy listing.
func attachedARNs(ps []iamtypes.AttachedPolicy) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if a := aws.ToString(p.PolicyArn); a != "" {
			out = append(out, a)
		}
	}
	return out
}
