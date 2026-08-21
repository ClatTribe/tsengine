package cloudiam

import "strings"

// candidates.go answers a question the evaluator alone cannot: WHICH resource should a
// "can this principal escalate?" question be asked about.
//
// Every caller used to ask about the literal resource "*", and that is wrong in a way
// that only ever loses findings. "*" as a REQUEST resource means "the resource actually
// named *", which no real ARN is, so any statement scoped to anything at all — the shape
// a half-decent least-privilege policy takes — answers "not allowed" and the escalation
// disappears. BishopFox's own control set separates the two cases precisely:
//
//	fn2  Allow iam:CreatePolicyVersion on arn:aws:iam::*:policy/fn2-*   → EXPLOITABLE
//	fp4  Allow iam:CreatePolicyVersion on arn:aws:iam::aws:policy/fp4-* → NOT exploitable
//
// Same action, same wildcard, opposite answers, and the only difference is the ACCOUNT
// segment. `aws` there is not an account id — it is the namespace AWS owns, holding the
// AWS-managed policies. Nobody can create a policy version in it, so the permission is
// inert. Anything else in that segment is a customer-managed policy the caller can
// rewrite, which is a straight path to admin.
//
// So the resource constraint has to be READ, not discarded, and read with one specific
// piece of AWS knowledge that no amount of glob matching supplies.

// CandidateResources derives concrete resource ARNs that the ALLOW statements in these
// documents genuinely reach, suitable for asking Authorize about.
//
// account is the principal's own account id, used where a pattern leaves the account
// segment open; "" falls back to a placeholder, which changes nothing about the
// decision because the pattern that produced it accepted any account.
//
// Grounded (§10) in the direction that matters:
//
//   - A pattern reaching ONLY the AWS-owned namespace yields no candidate, so a grant
//     that cannot touch a customer resource produces no escalation. That is a refusal,
//     not an omission: it is the fp4 answer, and it has to be reached deliberately
//     rather than by the accident of "*" matching nothing.
//   - A statement with no Resource, or Resource "*", yields "*" — it really does reach
//     everything.
//   - Deny statements seed nothing. Their resources are what the principal is forbidden
//     to touch; asking whether they can act there is asking the wrong question, and the
//     denies still apply to every candidate the allows produce.
//   - No allow statements at all → nil, and a caller that iterates gets no permission.
//     Never "*" as a consolation, which would invent access from an empty policy.
func CandidateResources(docs []*Document, account string) []string {
	if account == "" {
		account = "000000000000"
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, st := range d.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			// NotResource means "everything except", so it reaches ordinary resources.
			if len(st.Resource) == 0 || len(st.NotResource) > 0 {
				add("*")
				continue
			}
			for _, r := range st.Resource {
				if r == "*" {
					add("*")
					continue
				}
				if c, ok := ConcreteResource(r, account); ok {
					add(c)
				}
			}
		}
	}
	return out
}

// ConcreteResource turns one resource PATTERN into a concrete ARN a request could
// really carry, or reports that no customer-owned resource matches it.
//
// ok=false has exactly one cause today: the ARN's account segment is the literal `aws`,
// AWS's own namespace for managed policies. Every other wildcard is satisfiable, because
// the customer can name a resource to fit it.
func ConcreteResource(pattern, account string) (string, bool) {
	if pattern == "" {
		return "", false
	}
	if !strings.HasPrefix(pattern, "arn:") {
		// A non-ARN resource id (some services take bare names). A wildcard in it is
		// satisfiable by naming the resource; nothing here can rule it out.
		return strings.ReplaceAll(pattern, "*", "tsengine-target"), true
	}
	// arn:partition:service:region:account:resource — the resource segment may itself
	// contain colons, so split at most 6 ways.
	p := strings.SplitN(pattern, ":", 6)
	if len(p) < 6 {
		return strings.ReplaceAll(pattern, "*", "tsengine-target"), true
	}
	switch p[4] {
	case "aws":
		// The AWS-owned namespace. No customer resource lives here and nothing in it
		// can be written, so a grant scoped to it reaches nothing.
		return "", false
	case "", "*":
		p[4] = account
	}
	for i := range p {
		if i == 4 {
			continue
		}
		p[i] = strings.ReplaceAll(p[i], "*", "tsengine-target")
	}
	// The partition and service must stay real for a service-scoped policy to match.
	if p[1] == "tsengine-target" {
		p[1] = "aws"
	}
	return strings.Join(p, ":"), true
}
