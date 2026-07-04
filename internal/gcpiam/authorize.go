// Package gcpiam is the GCP analogue of internal/cloudiam: a faithful-but-pragmatic GCP IAM access
// decision, so the cloud attack-path engine can PRUNE over-approximated GCP edges the same way it prunes
// AWS ones (cloudiam was AWS-only — the documented multi-cloud-reasoning gap, ADR 0009 Phase 4b).
//
// GCP's model differs from AWS's: access is granted by IAM BINDINGS (role → members) attached at a node in
// the resource hierarchy (organization → folder → project → resource), and a binding is INHERITED by every
// descendant. A role grants a set of permissions; a binding may carry an IAM Condition (CEL) that gates it
// at runtime. IAM DENY policies override allows. So "may member M do permission P on resource R?" is:
//
//	1. If a Deny rule denies P for M (condition holds, M not excepted) anywhere up the hierarchy → DENY.
//	2. Else walk R and its ancestors; if any binding's role grants P AND M matches the binding's members →
//	   ALLOW (conditional when the binding carries an unresolved condition).
//	3. Else implicit-deny (GCP is deny-by-default).
//
// Conservatism (matches cloudiam + the prune's recall-preserving contract, §10): this is used to DROP an
// over-approximated edge ONLY on a DEFINITIVE deny. Anything uncertain — an unresolved condition, a group
// whose membership we can't resolve, a custom role whose permissions we don't have — yields `conditional`
// (a possible allow), which KEEPS the edge. We never drop a genuinely-reachable path on missing data.
package gcpiam

import (
	"encoding/json"
	"strings"
)

// ResourcePolicy is the JSON shape an ingest source attaches to a node (e.g. a service account's IAM
// policy, Node.Attrs["gcp_iam_policy"]): the bindings + deny rules ON that resource, plus any role
// definitions in scope. ParseResourcePolicy decodes it into a single-Resource PolicySet the prune checks.
type ResourcePolicy struct {
	Bindings []Binding           `json:"bindings,omitempty"`
	Denies   []DenyRule          `json:"denies,omitempty"`
	Roles    map[string][]string `json:"roles,omitempty"`
}

// ParseResourcePolicy decodes a node's attached GCP IAM policy into a PolicySet (one resource, no ancestor
// chain — the attached policy is what the ingest source captured). Returns ok=false on malformed JSON so the
// caller can fail OPEN (keep the edge), mirroring cloudiam's "unparseable policy ⇒ authorized".
func ParseResourcePolicy(b []byte) (PolicySet, bool) {
	var rp ResourcePolicy
	if err := json.Unmarshal(b, &rp); err != nil {
		return PolicySet{}, false
	}
	return PolicySet{
		Resource: &Resource{Bindings: rp.Bindings},
		Roles:    rp.Roles,
		Denies:   rp.Denies,
	}, true
}

// Decision mirrors cloudiam.Decision for a consistent caller experience.
type Decision string

const (
	Allow        Decision = "allow"
	ImplicitDeny Decision = "implicit_deny" // no binding grants it (deny-by-default)
	ExplicitDeny Decision = "explicit_deny" // an IAM Deny rule blocks it
)

// Binding is one IAM policy binding: a role granted to members, optionally condition-gated.
type Binding struct {
	Role      string   `json:"role"`              // e.g. "roles/storage.objectAdmin" or "projects/p/roles/custom"
	Members   []string `json:"members"`           // "user:a@x", "serviceAccount:a@x", "group:g@x", "domain:x", "allUsers", "allAuthenticatedUsers"
	Condition string   `json:"condition,omitempty"` // a CEL expression; non-empty → we treat the binding as condition-gated
}

// DenyRule is an IAM Deny policy rule (deny overrides allow).
type DenyRule struct {
	DeniedPermissions   []string `json:"denied_permissions"`             // exact perms or "*"
	DeniedPrincipals    []string `json:"denied_principals"`              // members (or "principalSet://.../allUsers")
	ExceptionPrincipals []string `json:"exception_principals,omitempty"` // members exempted from this deny
	Condition           string   `json:"condition,omitempty"`            // unresolved → treated as NOT denying (like cloudiam)
}

// Resource is a node in the IAM hierarchy. Parent chains up (resource → project → folder → org); a request
// on a Resource is evaluated against its bindings PLUS every ancestor's (inheritance).
type Resource struct {
	Name     string    `json:"name"`
	Bindings []Binding `json:"bindings,omitempty"`
	Parent   *Resource `json:"-"`
}

// PolicySet is everything bearing on the request: the leaf resource (with its ancestor chain), the role→
// permissions definitions in scope, and any deny policies. Roles may be empty — basic roles (owner/editor/
// viewer) are understood inline, and an UNKNOWN role is treated as possibly-granting (conditional) so we
// never over-prune.
type PolicySet struct {
	Resource *Resource
	Roles    map[string][]string // role name → the permissions it grants ("*" = all)
	Denies   []DenyRule
}

// Request is one access question.
type Request struct {
	Member     string // the principal, e.g. "serviceAccount:sa@p.iam.gserviceaccount.com"
	Permission string // e.g. "storage.objects.get"
}

// Authorize returns the decision and whether the deciding allow is condition-gated (uncertain).
func Authorize(req Request, ps PolicySet) (Decision, bool) {
	// 1. Deny rules win — but ONLY when they definitively apply. A deny whose principal match is
	//    uncertain (a group whose membership we can't resolve) is a POSSIBLE deny, not a definitive one:
	//    treating it as ExplicitDeny would over-prune a possibly-reachable edge (§10 — drop only on a
	//    DEFINITIVE deny; the allow side is already symmetric via memberSure). A possible deny instead
	//    makes any subsequent allow conditional (allowed unless the deny turns out to apply).
	denyPossible := false
	for _, d := range ps.Denies {
		if d.Condition != "" {
			continue // unresolved deny condition → not denying (conservative, mirrors cloudiam)
		}
		if !permIn(d.DeniedPermissions, req.Permission) {
			continue
		}
		if memberInExact(d.ExceptionPrincipals, req.Member) {
			continue // explicitly excepted
		}
		if m, certain := memberMatch(d.DeniedPrincipals, req.Member); m {
			if certain {
				return ExplicitDeny, false
			}
			denyPossible = true // uncertain group deny — not definitive; downgrade any allow to conditional
		}
	}

	// 2. Walk the resource + ancestors; a binding grants access when its role includes the permission and
	//    the member matches. A FIRM allow needs all of: role known to grant, member certain, no condition.
	//    Anything short of that but still possibly-granting (unresolved condition, unresolvable group, or a
	//    custom role whose perms we don't have) is CONDITIONAL — a possible allow that keeps the edge.
	var allow, cond bool
	for r := ps.Resource; r != nil; r = r.Parent {
		for _, b := range r.Bindings {
			memberHit, memberSure := memberMatch(b.Members, req.Member)
			if !memberHit {
				continue
			}
			grants, roleKnown := roleGrants(ps.Roles, b.Role, req.Permission)
			if roleKnown && !grants {
				continue // this role definitively does not grant the permission
			}
			if grants && roleKnown && memberSure && b.Condition == "" {
				allow = true
			} else {
				cond = true // possible allow gated by a condition / unknown role / unresolved group
			}
		}
	}
	switch {
	case allow:
		return Allow, cond || denyPossible // a firm allow shadowed by a possible deny is conditional
	case cond:
		return Allow, true
	default:
		return ImplicitDeny, false
	}
}

// Permits is the convenience boolean.
func Permits(req Request, ps PolicySet) (allowed, conditional bool) {
	d, c := Authorize(req, ps)
	return d == Allow, c
}

// roleGrants reports whether role includes permission, and whether the role's definition was KNOWN (so the
// caller can distinguish "known not to grant" from "unknown — treat as possible"). Basic roles are understood
// inline; a role present in roles uses its permission list ("*" = all); an absent custom role is unknown.
func roleGrants(roles map[string][]string, role, perm string) (grants, known bool) {
	switch role {
	case "roles/owner", "roles/editor":
		return true, true // broad write roles grant effectively any service permission
	case "roles/viewer":
		return isReadPerm(perm), true // viewer grants read-only
	}
	perms, ok := roles[role]
	if !ok {
		return false, false // custom/unknown role — permissions not in scope
	}
	for _, p := range perms {
		if p == "*" || p == perm || globGrants(p, perm) {
			return true, true
		}
	}
	return false, true
}

// isReadPerm classifies a permission as read-only by its verb suffix (GCP convention service.resource.verb).
func isReadPerm(perm string) bool {
	i := strings.LastIndex(perm, ".")
	if i < 0 {
		return false
	}
	switch perm[i+1:] {
	case "get", "list", "view", "getIamPolicy", "check", "read", "export":
		return true
	}
	return false
}

// globGrants matches a permission pattern like "storage.objects.*" against a concrete permission.
func globGrants(pattern, perm string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(perm, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == perm
}

// memberMatch reports whether any of the binding's members covers the request member, and whether the match
// is CERTAIN. allUsers / allAuthenticatedUsers / exact / domain are certain; a group binding is uncertain
// (we can't resolve membership) → it returns (true, false) so the caller treats it as a possible (keep) match.
func memberMatch(members []string, member string) (hit, certain bool) {
	for _, m := range members {
		switch {
		case m == "allUsers", m == "allAuthenticatedUsers":
			return true, true // public binding — anyone (we treat any concrete principal as authenticated)
		case m == member:
			return true, true
		case strings.HasPrefix(m, "domain:"):
			if domainOf(member) == strings.TrimPrefix(m, "domain:") {
				return true, true
			}
		case strings.HasPrefix(m, "group:"):
			hit = true // we can't resolve group membership → possible match (uncertain)
		}
	}
	if hit {
		return true, false
	}
	return false, false
}

func memberInExact(members []string, member string) bool {
	for _, m := range members {
		if m == member {
			return true
		}
	}
	return false
}

func domainOf(member string) string {
	at := strings.LastIndex(member, "@")
	if at < 0 {
		return ""
	}
	dom := member[at+1:]
	// service accounts look like sa@PROJECT.iam.gserviceaccount.com — the org domain isn't derivable, so
	// only user/group emails yield a usable domain. Strip a trailing gserviceaccount suffix to avoid a
	// false domain match.
	if strings.HasSuffix(dom, ".iam.gserviceaccount.com") || strings.HasSuffix(dom, ".gserviceaccount.com") {
		return ""
	}
	return dom
}

func permIn(perms []string, perm string) bool {
	for _, p := range perms {
		if p == "*" || p == perm || globGrants(p, perm) {
			return true
		}
	}
	return false
}
