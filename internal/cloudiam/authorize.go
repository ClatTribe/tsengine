package cloudiam

import (
	"encoding/json"
	"net"
	"strings"
)

// Authorize is the full AWS access decision — a faithful-but-pragmatic subset of
// the IAM policy evaluation logic, layering the dimensions the old Eval ignored:
// RESOURCE-based policies (bucket/KMS/SQS policies), SERVICE CONTROL POLICIES
// (org guardrails), and CONDITION evaluation against a request context. These are
// the parts that often DECIDE real access — closing the "config-possible vs
// actually-allowed" gap (docs/design/cloud-engine-overfitting.md).
//
// Decision order (AWS "is the request allowed?" flowchart, condensed):
//   1. An explicit Deny in ANY policy (identity / resource / boundary / SCP) whose
//      condition holds → DENY.
//   2. SCPs are an org ceiling: if any SCP is attached, some SCP must Allow.
//   3. The permission boundary is a ceiling: if set, it must Allow.
//   4. Access is granted if an identity policy Allows OR — same-account — the
//      resource policy Allows this principal. Cross-account needs BOTH sides.
//   5. A deciding Allow gated by a condition we cannot resolve from Context yields
//      conditional=true (config-possible; needs live confirmation — the rung-3
//      floor, ADR 0002).
//
// Documented simplifications: SCP/boundary condition keys are not evaluated
// (treated as plain ceilings); an indeterminate Deny condition is treated as
// not-denying (the common deny is unconditional). Both are noted where they bite.

// Request is one authorization question with its condition context (keys like
// aws:MultiFactorAuthPresent, aws:SourceIp, aws:PrincipalTag/team, ...).
type Request struct {
	Principal string
	Action    string
	Resource  string
	Context   map[string]string
}

// PolicySet is every policy bearing on a request. Any field may be nil/empty.
type PolicySet struct {
	Identity       []*Document // identity-based (attached/inline) policies of the principal
	Boundary       *Document   // permission boundary (a ceiling)
	SCPs           []*Document // service control policies on the account's OU path (a ceiling)
	ResourcePolicy *Document   // resource-based policy on the target (e.g. S3 bucket policy)
	SameAccount    bool        // principal + resource in the same account (union rule applies)
}

// Authorize returns the decision and whether the deciding allow is condition-gated.
func Authorize(req Request, ps PolicySet) (Decision, bool) {
	idn := scanIdentity(req, ps.Identity)
	res := scanResource(req, ps.ResourcePolicy)
	bnd := scanCeiling(req, docsOf(ps.Boundary))
	scp := scanCeiling(req, ps.SCPs)

	// 1. explicit Deny anywhere wins.
	if idn.deny || res.deny || bnd.deny || scp.deny {
		return ExplicitDeny, false
	}
	// 2. SCP ceiling.
	if len(ps.SCPs) > 0 && !scp.allow {
		return ImplicitDeny, false
	}
	// 3. permission boundary ceiling.
	if ps.Boundary != nil && !bnd.allow {
		return ImplicitDeny, false
	}
	// 4. identity OR (same-account) resource policy; cross-account needs both.
	if ps.SameAccount {
		if idn.allow || res.allow {
			return Allow, false
		}
		if idn.cond || res.cond {
			return Allow, true
		}
		return ImplicitDeny, false
	}
	// cross-account
	if idn.allow && res.allow {
		return Allow, false
	}
	if (idn.allow || idn.cond) && (res.allow || res.cond) {
		return Allow, true
	}
	return ImplicitDeny, false
}

// Permits is the convenience boolean: allowed (possibly conditionally).
func Permits(req Request, ps PolicySet) (allowed, conditional bool) {
	dec, cond := Authorize(req, ps)
	return dec == Allow, cond
}

// scan is the per-policy-set result.
type scan struct {
	allow bool // an Allow matched with a satisfied/absent condition
	cond  bool // an Allow matched but is gated by an unresolved condition
	deny  bool // a Deny matched with a satisfied/absent condition
}

// scanIdentity evaluates identity-style docs (no Principal element).
func scanIdentity(req Request, docs []*Document) scan {
	var r scan
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, st := range d.Statement {
			if !st.matches(req.Action, req.Resource) {
				continue
			}
			applyStatement(&r, st, req.Context)
		}
	}
	return r
}

// scanResource evaluates a resource-based policy: statements must also name the
// requesting principal (or "*").
func scanResource(req Request, d *Document) scan {
	var r scan
	if d == nil {
		return r
	}
	for _, st := range d.Statement {
		if !st.matches(req.Action, req.Resource) {
			continue
		}
		if matched, present := principalMatches(st.Principal, req.Principal); present && !matched {
			continue
		}
		applyStatement(&r, st, req.Context)
	}
	return r
}

// scanCeiling evaluates boundary/SCP docs as plain ceilings (conditions on these
// are not evaluated in this subset — see the package note).
func scanCeiling(req Request, docs []*Document) scan {
	var r scan
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, st := range d.Statement {
			if !st.matches(req.Action, req.Resource) {
				continue
			}
			if strings.EqualFold(st.Effect, "Deny") {
				// Ceilings evaluate no condition context — so a CONDITIONED ceiling deny is INDETERMINATE,
				// not definitive. Treating it as an unconditional deny over-prunes a genuinely-reachable
				// edge (§10: drop only on a DEFINITIVE deny; keep on uncertain — the same rule the
				// identity/resource path already applies). Only an UNCONDITIONAL ceiling deny definitively
				// denies; a conditioned one is left as a possible deny that doesn't prune.
				if len(st.Condition) == 0 {
					r.deny = true
				}
			} else if strings.EqualFold(st.Effect, "Allow") {
				r.allow = true
			}
		}
	}
	return r
}

func applyStatement(r *scan, st Statement, ctx map[string]string) {
	sat, evaluable := evalCondition(st.Condition, ctx)
	uncond := len(st.Condition) == 0
	if strings.EqualFold(st.Effect, "Deny") {
		// A deny applies only when its condition holds (or it is unconditional).
		// An indeterminate deny condition is treated as not-denying.
		if uncond || (evaluable && sat) {
			r.deny = true
		}
		return
	}
	if strings.EqualFold(st.Effect, "Allow") {
		switch {
		case uncond || (evaluable && sat):
			r.allow = true
		case !evaluable:
			r.cond = true // gated by a condition we can't resolve from context
		}
	}
}

// evalCondition reports whether a Condition block is satisfied by ctx, and whether
// it could be decided at all. Operators are AND'd; keys within an operator are
// AND'd; values for a key are OR'd (AWS semantics). An absent context key or an
// unsupported operator makes the clause indeterminate (evaluable=false).
func evalCondition(cond map[string]interface{}, ctx map[string]string) (satisfied, evaluable bool) {
	if len(cond) == 0 {
		return true, true
	}
	decided := true
	for op, kvAny := range cond {
		kv, ok := kvAny.(map[string]interface{})
		if !ok {
			decided = false
			continue
		}
		for key, valAny := range kv {
			vals := toStrings(valAny)
			ctxVal, present := ctx[key]
			if !present {
				decided = false
				continue
			}
			match, known := matchOp(op, ctxVal, vals)
			if !known {
				decided = false
				continue
			}
			if !match {
				return false, true // definitively not satisfied
			}
		}
	}
	if decided {
		return true, true
	}
	return false, false
}

func matchOp(op, ctxVal string, vals []string) (match, known bool) {
	switch op {
	case "Bool", "StringEquals", "StringEqualsIgnoreCase", "ArnEquals":
		for _, v := range vals {
			if strings.EqualFold(op, "StringEqualsIgnoreCase") {
				if strings.EqualFold(ctxVal, v) {
					return true, true
				}
			} else if ctxVal == v {
				return true, true
			}
		}
		return false, true
	case "StringNotEquals":
		for _, v := range vals {
			if ctxVal == v {
				return false, true
			}
		}
		return true, true
	case "StringLike", "ArnLike":
		for _, v := range vals {
			if globMatch(v, ctxVal) {
				return true, true
			}
		}
		return false, true
	case "IpAddress":
		return ipInAny(ctxVal, vals), true
	case "NotIpAddress":
		return !ipInAny(ctxVal, vals), true
	default:
		return false, false
	}
}

func ipInAny(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			if ip.Equal(net.ParseIP(c)) {
				return true
			}
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// principalMatches reports whether a resource-policy statement's Principal element
// covers the requesting principal. present=false means the statement has no
// Principal (i.e. it is not a resource-policy statement).
func principalMatches(raw json.RawMessage, principal string) (matched, present bool) {
	if len(raw) == 0 {
		return false, false
	}
	if strings.TrimSpace(string(raw)) == `"*"` {
		return true, true
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil && len(obj) > 0 {
		if aws, ok := obj["AWS"]; ok {
			for _, p := range toStringsRaw(aws) {
				if p == "*" || p == principal || globMatch(p, principal) || rootCovers(p, principal) {
					return true, true
				}
			}
		}
		return false, true
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == "*" || one == principal || globMatch(one, principal), true
	}
	return false, true
}

// rootCovers handles the common "account root grants any principal in that
// account": arn:aws:iam::ACCT:root covers arn:aws:iam::ACCT:role/... .
func rootCovers(grant, principal string) bool {
	if !strings.HasSuffix(grant, ":root") {
		return false
	}
	acct := accountOf(grant)
	return acct != "" && accountOf(principal) == acct
}

func accountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func docsOf(d *Document) []*Document {
	if d == nil {
		return nil
	}
	return []*Document{d}
}

func toStrings(v interface{}) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func toStringsRaw(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}
