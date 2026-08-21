// Package cloudiam is the IAM effective-permissions evaluator — the `resolve_access`
// brain (ADR 0002 / docs/design §2). It turns raw AWS IAM policy documents into
// "what can this principal actually do", which the snapshot ingest uses to
// compute the graph's has_access / assume_role / privesc edges.
//
// Pure Go, no AWS: policy evaluation is a deterministic algorithm over policy
// JSON. Conditions are *recorded* (an allow under a condition is "conditional"),
// not fully evaluated — a conditioned grant is config-possible but may be
// blocked at runtime, which is exactly the live-validation gap (ADR 0002).
package cloudiam

import (
	"encoding/json"
	"strings"
)

// Document is an IAM policy document.
type Document struct {
	Version   string      `json:"Version,omitempty"`
	Statement []Statement `json:"Statement"`
}

// Statement is one IAM statement. Action/Resource/etc. may each be a single
// string or an array in AWS JSON, so they decode through stringOrSlice.
type Statement struct {
	Sid         string        `json:"Sid,omitempty"`
	Effect      string        `json:"Effect"` // "Allow" | "Deny"
	Action      stringOrSlice `json:"Action,omitempty"`
	NotAction   stringOrSlice `json:"NotAction,omitempty"`
	Resource    stringOrSlice `json:"Resource,omitempty"`
	NotResource stringOrSlice `json:"NotResource,omitempty"`
	// Principal appears on RESOURCE-based policies (bucket/KMS/trust policies):
	// "*", "arn", ["arn",...], or {"AWS":...,"Service":...}. Absent on
	// identity-based policies. Kept raw and interpreted by principalMatches.
	Principal    json.RawMessage        `json:"Principal,omitempty"`
	NotPrincipal json.RawMessage        `json:"NotPrincipal,omitempty"`
	Condition    map[string]interface{} `json:"Condition,omitempty"`
}

// stringOrSlice decodes a JSON value that is either a string or []string.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '[' {
		var xs []string
		if err := json.Unmarshal(b, &xs); err != nil {
			return err
		}
		*s = xs
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*s = []string{one}
	return nil
}

// Parse decodes a policy document from JSON.
func Parse(b []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Decision is the result of evaluating an (action, resource) against a policy.
type Decision int

const (
	ImplicitDeny Decision = iota // no statement matched → deny
	Allow                        // an Allow matched and no Deny did
	ExplicitDeny                 // a Deny matched → wins over any Allow
)

// Eval evaluates whether `action` on `resource` is permitted by the documents,
// with AWS semantics: an explicit Deny always wins; otherwise an Allow grants;
// otherwise implicit deny. The second return is true if the deciding Allow
// carried a Condition (a runtime gate → the grant is "conditional").
func Eval(action, resource string, docs ...*Document) (Decision, bool) {
	allowed := false
	conditional := false
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, st := range d.Statement {
			if !st.matches(action, resource) {
				continue
			}
			// Conditions are DECIDED where they can be, not merely counted. Eval used to
			// ask only whether a Condition block was present, which made every gated
			// grant equally uncertain — a permission whose window closed in 2020 read the
			// same as one gated on MFA. applies=false means the statement does not fire
			// at all; firm=false means it fires but we could not resolve the gate.
			applies, firm := conditionState(st.Condition)
			if !applies {
				continue
			}
			if strings.EqualFold(st.Effect, "Deny") {
				// A CONDITIONED deny only applies when its condition holds — which we don't evaluate. So
				// it is NOT a definitive deny: treating it as one over-denies and drops a possibly-reachable
				// edge/privesc path (§10 — keep on uncertain, drop only on a DEFINITIVE deny; matches the
				// sibling authorize.go's "indeterminate deny condition is not-denying"). The grant becomes
				// conditional (allowed unless the deny fires) rather than denied. An UNCONDITIONAL deny
				// still wins outright.
				if !firm {
					conditional = true
					continue
				}
				return ExplicitDeny, false
			}
			if strings.EqualFold(st.Effect, "Allow") {
				allowed = true
				if !firm {
					conditional = true
				}
			}
		}
	}
	if allowed {
		return Allow, conditional
	}
	return ImplicitDeny, false
}

// Allows is a convenience: true iff the action on the resource is permitted
// (Allow, not denied). The bool reports whether it's conditional.
func Allows(action, resource string, docs ...*Document) (bool, bool) {
	dec, cond := Eval(action, resource, docs...)
	return dec == Allow, cond
}

// matches reports whether a statement's Action/Resource (honouring NotAction /
// NotResource) cover the (action, resource) pair.
func (st Statement) matches(action, resource string) bool {
	if !actionMatch(st.Action, st.NotAction, action) {
		return false
	}
	if !resourceMatch(st.Resource, st.NotResource, resource) {
		return false
	}
	return true
}

func actionMatch(actions, notActions stringOrSlice, action string) bool {
	if len(notActions) > 0 {
		for _, p := range notActions {
			if globMatchFold(p, action) {
				return false // NotAction: matches everything EXCEPT these
			}
		}
		return true
	}
	for _, p := range actions {
		if globMatchFold(p, action) {
			return true
		}
	}
	return false
}

func resourceMatch(resources, notResources stringOrSlice, resource string) bool {
	// An empty Resource (e.g. identity-based statements sometimes omit it in
	// our simplified inputs) is treated as "*".
	if len(resources) == 0 && len(notResources) == 0 {
		return true
	}
	if len(notResources) > 0 {
		for _, p := range notResources {
			if globMatch(p, resource) {
				return false
			}
		}
		return true
	}
	for _, p := range resources {
		if globMatch(p, resource) {
			return true
		}
	}
	return false
}

// globMatchFold is case-insensitive glob match (IAM actions are case-insensitive).
func globMatchFold(pattern, s string) bool {
	return globMatch(strings.ToLower(pattern), strings.ToLower(s))
}

// globMatch matches a string against an IAM-style glob supporting `*` (any run)
// and `?` (any one char). Linear two-pointer with backtracking.
func globMatch(pattern, s string) bool {
	var si, pi, star, ss int
	star = -1
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			ss = si
			pi++
		} else if star != -1 {
			pi = star + 1
			ss++
			si = ss
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// conditionState resolves a statement's Condition block as far as it can without a
// request context.
//
//	applies=false  the condition is decidable and NOT satisfied — the statement does
//	               not fire. A grant whose date window has passed is not a grant, and
//	               a deny whose window has passed does not deny.
//	firm=true      no condition, or one decidable and satisfied — treat as unconditional.
//	firm=false     a real gate we cannot resolve from here (MFA, source IP, a tag).
//	               The grant is config-possible and stays rung-3 (ADR 0002).
//
// The only conditions decidable with no context are date bounds on the request-time
// keys, which AWS sets itself on every request — see evalRequestTimeCondition. Everything
// else remains indeterminate, so this can only sharpen an answer, never invent one.
func conditionState(cond map[string]interface{}) (applies, firm bool) {
	if len(cond) == 0 {
		return true, true
	}
	satisfied, evaluable := evalCondition(cond, nil)
	if !evaluable {
		return true, false
	}
	return satisfied, satisfied
}
