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
			if strings.EqualFold(st.Effect, "Deny") {
				return ExplicitDeny, false
			}
			if strings.EqualFold(st.Effect, "Allow") {
				allowed = true
				if len(st.Condition) > 0 {
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
