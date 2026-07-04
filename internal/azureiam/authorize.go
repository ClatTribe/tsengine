// Package azureiam is the Azure analogue of cloudiam/gcpiam: a faithful-but-pragmatic Azure RBAC access
// decision, completing the AWS+GCP+Azure effective-permission trio so the cloud attack-path engine can PRUNE
// over-approximated Azure edges instead of leaving them at "config-possible" (ADR-0009 Phase-4b).
//
// Azure RBAC: access comes from ROLE ASSIGNMENTS (principal + role definition + scope). A scope is a node in
// the hierarchy management-group → subscription → resource-group → resource, and an assignment is INHERITED by
// every descendant. A role DEFINITION grants Actions (and DataActions) minus NotActions (the exclusions). DENY
// assignments override allows. ABAC conditions gate an assignment at runtime.
//
// "May principal P do action A on scope S?" =
//  1. A deny assignment covering A for P (condition holds, P not excluded) up the scope chain → DENY.
//  2. Else walk S + ancestors; an assignment whose role def grants A (A matches an Action glob and no NotAction
//     glob) AND whose principals include P → ALLOW (conditional on an unresolved condition / group / unknown role).
//  3. Else implicit-deny (RBAC is deny-by-default).
//
// Conservatism is load-bearing (matches cloudiam/gcpiam + the prune's recall-preserving contract, §10): used to
// DROP an over-approximated edge ONLY on a DEFINITIVE deny; every uncertainty yields a CONDITIONAL allow that
// KEEPS the edge.
package azureiam

import (
	"encoding/json"
	"strings"
)

// Decision mirrors cloudiam/gcpiam.
type Decision string

const (
	Allow        Decision = "allow"
	ImplicitDeny Decision = "implicit_deny"
	ExplicitDeny Decision = "explicit_deny"
)

// RoleDef is a role definition's effective permission set: an action is granted iff it matches an Action glob
// and matches NO NotAction glob.
type RoleDef struct {
	Actions    []string `json:"actions"`               // e.g. ["*"] (Owner) or ["*/read"] (Reader)
	NotActions []string `json:"not_actions,omitempty"` // excluded actions (e.g. Contributor excludes role-assignment writes)
}

// Assignment is a role assigned to principals at a scope, optionally ABAC-condition-gated.
type Assignment struct {
	Role       string   `json:"role"`                // role-definition name (built-in like "Owner" or a custom def id)
	Principals []string `json:"principals"`          // object ids / "user:..", "sp:..", "group:.." (matched literally; group = uncertain)
	Condition  string   `json:"condition,omitempty"` // ABAC condition; non-empty → condition-gated
}

// DenyAssignment overrides allows.
type DenyAssignment struct {
	Actions           []string `json:"actions"`
	NotActions        []string `json:"not_actions,omitempty"`
	Principals        []string `json:"principals"`
	ExcludePrincipals []string `json:"exclude_principals,omitempty"`
	Condition         string   `json:"condition,omitempty"`
}

// Scope is a node in the RBAC hierarchy; Parent chains up (resource → resource-group → subscription → mgmt-group).
type Scope struct {
	Name        string       `json:"name"`
	Assignments []Assignment `json:"assignments,omitempty"`
	Parent      *Scope       `json:"-"`
}

// PolicySet is everything bearing on the request. Roles may be empty — built-in roles (Owner/Contributor/Reader)
// are understood inline; an unknown custom role is treated as possibly-granting (conditional) so we never over-prune.
type PolicySet struct {
	Scope   *Scope
	Roles   map[string]RoleDef // role name → definition
	Denies  []DenyAssignment
}

// Request is one access question.
type Request struct {
	Principal string // object id / "user:..", "sp:.." (a managed identity is an sp)
	Action    string // e.g. "Microsoft.Storage/storageAccounts/blobServices/containers/read"
}

// Authorize returns the decision and whether the deciding allow is condition-gated (uncertain).
func Authorize(req Request, ps PolicySet) (Decision, bool) {
	// 1. Deny assignments win — but ONLY when they definitively apply. A deny whose principal match is
	//    uncertain (a group whose membership we can't resolve) is a POSSIBLE deny, not a definitive one:
	//    treating it as ExplicitDeny would over-prune a possibly-reachable edge (§10 — drop only on a
	//    DEFINITIVE deny; the allow side is already symmetric via `sure`). A possible deny instead makes
	//    any subsequent allow conditional (allowed unless the deny turns out to apply).
	denyPossible := false
	for _, d := range ps.Denies {
		if d.Condition != "" {
			continue // unresolved condition → not denying (conservative)
		}
		if !actionMatches(d.Actions, d.NotActions, req.Action) {
			continue
		}
		if principalInExact(d.ExcludePrincipals, req.Principal) {
			continue
		}
		if hit, certain := principalMatch(d.Principals, req.Principal); hit {
			if certain {
				return ExplicitDeny, false
			}
			denyPossible = true // uncertain group deny — not definitive; downgrade any allow to conditional
		}
	}

	// 2. Walk scope + ancestors.
	var allow, cond bool
	for sc := ps.Scope; sc != nil; sc = sc.Parent {
		for _, a := range sc.Assignments {
			hit, sure := principalMatch(a.Principals, req.Principal)
			if !hit {
				continue
			}
			grants, roleKnown := roleGrants(ps.Roles, a.Role, req.Action)
			if roleKnown && !grants {
				continue // this role definitively does not grant the action
			}
			if grants && roleKnown && sure && a.Condition == "" {
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

// roleGrants reports whether the role grants the action, and whether the role definition was KNOWN. Built-in
// roles are understood inline; a role in roles uses its Actions/NotActions; an absent custom role is unknown.
func roleGrants(roles map[string]RoleDef, role, action string) (grants, known bool) {
	switch strings.ToLower(role) {
	case "owner":
		return true, true // Actions ["*"]
	case "contributor":
		// ["*"] minus management actions (role assignment / elevate) — model the security-relevant exclusion.
		if isAuthorizationWrite(action) {
			return false, true
		}
		return true, true
	case "reader":
		return isReadAction(action), true
	}
	def, ok := roles[role]
	if !ok {
		return false, false // unknown custom role
	}
	return actionMatches(def.Actions, def.NotActions, action), true
}

// actionMatches reports whether action matches an Actions glob and no NotActions glob (Azure semantics).
func actionMatches(actions, notActions []string, action string) bool {
	matched := false
	for _, a := range actions {
		if azGlob(a, action) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, na := range notActions {
		if azGlob(na, action) {
			return false
		}
	}
	return true
}

// azGlob matches an Azure action pattern (case-insensitive; "*" segments) against a concrete action.
func azGlob(pattern, action string) bool {
	p, a := strings.ToLower(pattern), strings.ToLower(action)
	if p == "*" || p == a {
		return true
	}
	if strings.HasSuffix(p, "/*") {
		return strings.HasPrefix(a, strings.TrimSuffix(p, "*"))
	}
	if strings.HasPrefix(p, "*/") { // e.g. "*/read"
		return strings.HasSuffix(a, strings.TrimPrefix(p, "*"))
	}
	if strings.Contains(p, "*") { // generic single-* glob
		i := strings.IndexByte(p, '*')
		return strings.HasPrefix(a, p[:i]) && strings.HasSuffix(a, p[i+1:])
	}
	return false
}

func isReadAction(action string) bool {
	a := strings.ToLower(action)
	return strings.HasSuffix(a, "/read") || strings.HasSuffix(a, "/list")
}

// isAuthorizationWrite flags the privilege-management actions Contributor excludes (so it can't self-escalate).
func isAuthorizationWrite(action string) bool {
	a := strings.ToLower(action)
	if !strings.HasPrefix(a, "microsoft.authorization/") {
		return false
	}
	return strings.HasSuffix(a, "/write") || strings.HasSuffix(a, "/delete") || strings.Contains(a, "elevateaccess")
}

// principalMatch reports whether any assignment principal covers the request principal and whether certain. A
// group principal is uncertain (membership unresolvable) → (true,false) so the caller keeps the edge.
func principalMatch(principals []string, principal string) (hit, certain bool) {
	for _, p := range principals {
		switch {
		case p == principal:
			return true, true
		case strings.HasPrefix(p, "group:"):
			hit = true // unresolved group membership → possible match
		}
	}
	if hit {
		return true, false
	}
	return false, false
}

func principalInExact(ps []string, principal string) bool {
	for _, p := range ps {
		if p == principal {
			return true
		}
	}
	return false
}

// ScopePolicy is the JSON an ingest source attaches to a node (Node.Attrs["azure_rbac_policy"]): the role
// assignments + deny assignments ON that scope plus the role definitions in scope.
type ScopePolicy struct {
	Assignments []Assignment       `json:"assignments,omitempty"`
	Denies      []DenyAssignment   `json:"denies,omitempty"`
	Roles       map[string]RoleDef `json:"roles,omitempty"`
}

// ParseScopePolicy decodes a node's attached Azure RBAC policy into a single-scope PolicySet. ok=false on
// malformed JSON so the caller fails OPEN (keeps the edge), mirroring cloudiam/gcpiam.
func ParseScopePolicy(b []byte) (PolicySet, bool) {
	var sp ScopePolicy
	if err := json.Unmarshal(b, &sp); err != nil {
		return PolicySet{}, false
	}
	return PolicySet{
		Scope:  &Scope{Assignments: sp.Assignments},
		Roles:  sp.Roles,
		Denies: sp.Denies,
	}, true
}
