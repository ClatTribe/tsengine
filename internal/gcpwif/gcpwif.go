// Package gcpwif models GCP Workload Identity Federation — the GCP half of the same
// question ghoidc asks of AWS: can a GitHub Actions workflow reach this cloud, and was
// that intended?
//
// WHY IT IS A SEPARATE PACKAGE AND NOT A GCP BRANCH OF ghoidc. AWS puts the whole
// decision in one document: a role's trust policy names the provider AND conditions the
// claims. GCP SPLITS IT ACROSS TWO OBJECTS THAT LIVE IN DIFFERENT PLACES AND ARE USUALLY
// EDITED BY DIFFERENT PEOPLE:
//
//  1. the POOL PROVIDER's attribute condition — which tokens the pool will accept at all
//  2. the SERVICE ACCOUNT's IAM binding      — which of those identities may impersonate it
//
// Neither half is sufficient, and neither half looks wrong on its own. A provider with no
// attribute condition is "fine, the bindings are narrow". A binding on the whole pool is
// "fine, the provider is conditioned". Put the two together and every GitHub repository
// on the internet can impersonate the service account. A scanner that reads one object at
// a time cannot see it — which is precisely why this is worth building, and why the join
// is a finding in its own right rather than a note on the other two.
//
// # Absence is provable; adequacy is not
//
// The attribute condition is a CEL expression. We do NOT interpret CEL — writing an
// expression evaluator to decide whether someone's condition is "good enough" would be an
// in-house engine (§13) making a judgement it cannot support. What is decidable without
// one:
//
//	ABSENT   → definite. No condition, no constraint. Reportable.
//	PRESENT  → we can say WHICH attributes it mentions (a lexical fact), and nothing more.
//	           We never conclude a present condition is adequate.
//
// So a repository-scoped condition downgrades a finding by removing our claim of
// unconstrained access; it never earns a clean bill of health we cannot verify.
package gcpwif

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

// GitHubIssuerURI is the issuer a GitHub-federating provider declares. Matched on the
// host so a trailing slash or scheme variation does not hide it.
const GitHubIssuerURI = "https://" + ghoidc.Issuer

// ImpersonationRoles are the roles that let a federated identity ACT AS a service
// account. A binding of any other role to a pool principal is not impersonation and is
// not this package's finding.
var ImpersonationRoles = map[string]bool{
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.serviceAccountUser":         true,
	"roles/owner":                          true,
	"roles/editor":                         true,
}

// Provider is one OIDC provider inside a workload identity pool.
type Provider struct {
	// PoolID and ID identify it; ProjectNumber is the numeric project the pool lives in
	// (WIF principals are addressed by number, not id).
	ProjectNumber string
	PoolID        string
	ID            string

	IssuerURI        string
	AllowedAudiences []string
	// AttributeMapping maps google.* and attribute.* to assertion.* expressions.
	AttributeMapping map[string]string
	// AttributeCondition is the CEL gate. Empty means there is none — the one thing we
	// can state definitively.
	AttributeCondition string
}

// FederatesGitHub reports whether this provider trusts GitHub Actions tokens.
func (p Provider) FederatesGitHub() bool {
	return strings.Contains(strings.ToLower(p.IssuerURI), ghoidc.Issuer)
}

// PoolResource is the pool's principal-namespace prefix, the string every binding on it
// begins with.
func (p Provider) PoolResource() string {
	return "iam.googleapis.com/projects/" + p.ProjectNumber +
		"/locations/global/workloadIdentityPools/" + p.PoolID
}

// ConditionMentions reports whether the attribute condition lexically references an
// assertion attribute. Lexical is all we claim: it answers "did they think about the
// repository at all", never "is this condition correct".
func (p Provider) ConditionMentions(attr string) bool {
	if p.AttributeCondition == "" {
		return false
	}
	c := p.AttributeCondition
	return strings.Contains(c, "assertion."+attr) || strings.Contains(c, "attribute."+attr)
}

// ServiceAccount is one GCP service account and the bindings on its own IAM policy.
type ServiceAccount struct {
	Email string
	// Privileged is supplied from real IAM data by the caller, never inferred here — the
	// same rule ghoidc follows for AWS.
	Privileged bool
	Bindings   []Binding
}

// Binding is one role granted to members on a service account.
type Binding struct {
	Role      string
	Members   []string
	Condition string
}

// PrincipalScope classifies how wide a WIF member string is.
type PrincipalScope int

const (
	// ScopeNotFederated: the member is not a workload-identity principal at all.
	ScopeNotFederated PrincipalScope = iota
	// ScopeEntirePool: principalSet://.../workloadIdentityPools/POOL/* — every identity
	// the pool can ever mint, including ones nobody has created yet.
	ScopeEntirePool
	// ScopeAttributeGroup: principalSet://.../attribute.NAME/VALUE — a group of identities
	// sharing an attribute (e.g. every repo in an org).
	ScopeAttributeGroup
	// ScopeExactSubject: principal://.../subject/SUB — one identity.
	ScopeExactSubject
)

// Member is one parsed WIF principal.
type Member struct {
	Raw       string
	Scope     PrincipalScope
	Pool      string // the pool resource path
	Attribute string // for ScopeAttributeGroup: "repository", "repository_owner", …
	Value     string // the attribute value, or the subject for ScopeExactSubject
}

// ParseMember reads a GCP IAM member string as a workload-identity principal.
//
// Grounded: a member we do not recognise as a WIF principal returns ScopeNotFederated
// rather than a guess. Ordinary members (user:, serviceAccount:, group:) are not this
// package's business.
func ParseMember(m string) Member {
	raw := strings.TrimSpace(m)
	var rest string
	switch {
	case strings.HasPrefix(raw, "principalSet://"):
		rest = strings.TrimPrefix(raw, "principalSet://")
	case strings.HasPrefix(raw, "principal://"):
		rest = strings.TrimPrefix(raw, "principal://")
	default:
		return Member{Raw: raw, Scope: ScopeNotFederated}
	}

	const marker = "/workloadIdentityPools/"
	i := strings.Index(rest, marker)
	if i < 0 {
		return Member{Raw: raw, Scope: ScopeNotFederated}
	}
	after := rest[i+len(marker):]
	poolID, tail, hasTail := strings.Cut(after, "/")
	pool := rest[:i+len(marker)] + poolID

	if !hasTail || tail == "" {
		// A bare pool with no selector: the whole pool, same blast radius as "/*".
		return Member{Raw: raw, Scope: ScopeEntirePool, Pool: pool}
	}
	if tail == "*" {
		return Member{Raw: raw, Scope: ScopeEntirePool, Pool: pool}
	}
	if strings.HasPrefix(tail, "subject/") {
		return Member{Raw: raw, Scope: ScopeExactSubject, Pool: pool,
			Value: strings.TrimPrefix(tail, "subject/")}
	}
	if strings.HasPrefix(tail, "attribute.") {
		attrAndVal := strings.TrimPrefix(tail, "attribute.")
		attr, val, _ := strings.Cut(attrAndVal, "/")
		return Member{Raw: raw, Scope: ScopeAttributeGroup, Pool: pool, Attribute: attr, Value: val}
	}
	// A selector shape we do not recognise. Reporting it as narrow would be a guess in
	// the dangerous direction, so it is treated as the whole pool and the caller can see
	// the raw string.
	return Member{Raw: raw, Scope: ScopeEntirePool, Pool: pool}
}

// Impersonates reports whether a binding's role lets its members act as the account.
func (b Binding) Impersonates() bool { return ImpersonationRoles[strings.TrimSpace(b.Role)] }

// RepositoryOf returns the "owner/repo" this member is scoped to, or "" when it is not
// scoped to a single repository.
func (m Member) RepositoryOf() string {
	switch m.Scope {
	case ScopeAttributeGroup:
		if m.Attribute == "repository" {
			return m.Value
		}
	case ScopeExactSubject:
		return ghoidc.RepositoryOfSubject(m.Value)
	}
	return ""
}
