package ghoidc

import (
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// trust.go analyses a role's trust policy for the GitHub-Actions weaknesses that
// hand a repository more of your cloud than anyone intended.
//
// THE OPERATOR DISTINCTION IS LOAD-BEARING. In IAM, `*` is a wildcard under
// StringLike and a LITERAL CHARACTER under StringEquals. So:
//
//	StringLike   {"...:sub": "repo:acme/*"}   → every repository in the org. Real.
//	StringEquals {"...:sub": "repo:acme/*"}   → matches a repository literally named
//	                                            "*", i.e. nothing. Fails CLOSED.
//
// The two look identical to a reader scanning for asterisks, and a scanner that
// treated them the same would report a critical finding against a policy that is
// merely broken. That is exactly the false confidence §10 forbids, so the operator
// decides whether an asterisk means anything at all.

// Weakness kinds. Each names a distinct way a trust policy over-trusts, because the
// remediation differs: an absent condition must be ADDED, a wildcard must be NARROWED.
const (
	// SubjectUnconstrained: the statement grants web-identity assumption to GitHub
	// with no `sub` condition whatsoever. Every repository on GitHub — not the org's,
	// anyone's — can mint a token this policy accepts.
	SubjectUnconstrained = "github_oidc_subject_unconstrained"
	// SubjectSpansRepositories: the `sub` pattern wildcards at or above the repository,
	// so any repo (optionally, any repo in the org) is trusted. In an org where members
	// can create repositories, this is self-service access to the role.
	SubjectSpansRepositories = "github_oidc_subject_spans_repositories"
	// SubjectSpansRefs: the repository is pinned but the ref/environment is not, so any
	// branch — including one a first-time contributor can push — assumes the role.
	SubjectSpansRefs = "github_oidc_subject_spans_refs"
	// AudienceUnconstrained: no `aud` condition, so a token minted for a different
	// relying party is accepted.
	AudienceUnconstrained = "github_oidc_audience_unconstrained"
)

// Weakness is one grounded defect in one trust statement.
type Weakness struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // critical | high | medium
	Sid      string `json:"sid,omitempty"`
	// Observed is the literal condition text we read, so a reader can check the verdict
	// against their own policy rather than trust ours.
	Observed string `json:"observed,omitempty"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

// TrustStatement is one statement that really does grant GitHub web-identity assumption.
type TrustStatement struct {
	Sid          string
	ProviderARNs []string
	// Subjects are the (operator, value) pairs conditioning `sub`; empty means none.
	Subjects  []Condition
	Audiences []Condition
	// Other are the remaining claim conditions (repository, ref, environment, actor …),
	// recorded so a strong policy that constrains via `repository` rather than `sub` is
	// not misread as unconstrained.
	Other []Condition
}

// Condition is one operator/value pair from a Condition block.
type Condition struct {
	Op    string `json:"op"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Wildcard reports whether this condition's value actually wildcards — which requires
// BOTH an asterisk and an operator under which an asterisk means something.
func (c Condition) Wildcard() bool {
	return strings.Contains(c.Value, "*") && likeOp(c.Op)
}

// Analysis is what a trust policy permits from GitHub Actions.
type Analysis struct {
	// Parsed is false when the document could not be read. Callers MUST NOT read an
	// empty Weaknesses list as "clean" without checking this: "we looked and found
	// nothing" and "we could not look" are different claims.
	Parsed bool
	// TrustsGitHub is false when no statement grants GitHub web-identity assumption —
	// this role is simply not reachable from Actions, and nothing below applies.
	TrustsGitHub bool
	Statements   []TrustStatement
	Weaknesses   []Weakness
	// OtherFederated names federated principals this analyser does NOT evaluate — an Okta or other
	// SAML/OIDC provider ARN that some statement grants role assumption to.
	//
	// It exists because "not GitHub" was silently indistinguishable from "no federation". A role a
	// customer's IdP can assume is a real identity transition into the cloud account, and dropping it
	// meant the estate read clean: the caller could not tell a role nobody federates into from one an
	// entire workforce IdP does. We do not assess these — the claim semantics differ per provider
	// (SAML uses saml:aud/saml:sub, not the GitHub sub grammar) and guessing at them would be the
	// wrong kind of confident — so this is DECLARED, not analysed. Same discipline as ReposComplete:
	// a check that cannot run says so rather than passing silently.
	OtherFederated []string
}

// Analyze reads a role's trust policy and reports its GitHub-OIDC weaknesses.
//
// Grounded (§10): a statement is considered only when it ALLOWS
// sts:AssumeRoleWithWebIdentity to a Federated principal that is the GitHub issuer.
// A Deny, a different action, or another identity provider produces nothing, and an
// unparseable document produces nothing with Parsed=false.
func Analyze(trustPolicy []byte) Analysis {
	doc, err := cloudiam.Parse(trustPolicy)
	if err != nil || doc == nil {
		return Analysis{}
	}
	a := Analysis{Parsed: true}

	for _, st := range doc.Statement {
		ts, ok := githubTrustStatement(st)
		if !ok {
			// Not a GitHub trust — but if it federates to SOMEONE, say so rather than dropping it.
			a.OtherFederated = append(a.OtherFederated, otherFederatedProviders(st)...)
			continue
		}
		a.TrustsGitHub = true
		a.Statements = append(a.Statements, ts)
		a.Weaknesses = append(a.Weaknesses, weaknessesFor(ts)...)
	}
	return a
}

// githubTrustStatement extracts a statement's GitHub-trust shape, or reports that this
// statement is not one.
func githubTrustStatement(st cloudiam.Statement) (TrustStatement, bool) {
	if !strings.EqualFold(st.Effect, "Allow") {
		return TrustStatement{}, false
	}
	if !hasWebIdentityAction(st.Action) {
		return TrustStatement{}, false
	}
	provs := federatedGitHubProviders(st.Principal)
	if len(provs) == 0 {
		return TrustStatement{}, false
	}
	ts := TrustStatement{Sid: st.Sid, ProviderARNs: provs}
	for _, c := range flattenConditions(st.Condition) {
		switch c.Key {
		case ClaimKey("sub"):
			ts.Subjects = append(ts.Subjects, c)
		case ClaimKey("aud"):
			ts.Audiences = append(ts.Audiences, c)
		default:
			if strings.HasPrefix(c.Key, Issuer+":") {
				ts.Other = append(ts.Other, c)
			}
		}
	}
	return ts, true
}

func hasWebIdentityAction(actions []string) bool {
	for _, a := range actions {
		la := strings.ToLower(strings.TrimSpace(a))
		// "*" and "sts:*" both cover it; an exact action must be the web-identity one.
		if la == "*" || la == "sts:*" || la == "sts:assumerolewithwebidentity" {
			return true
		}
	}
	return false
}

// hasSAMLAction is the SAML twin of hasWebIdentityAction. An Okta or ADFS federation into AWS is
// sts:AssumeRoleWithSAML, a DIFFERENT action from the OIDC one, so a check that only looked for
// web-identity would miss the most common enterprise SSO-into-cloud path entirely.
func hasSAMLAction(actions []string) bool {
	for _, a := range actions {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "*" || la == "sts:*" || la == "sts:assumerolewithsaml" {
			return true
		}
	}
	return false
}

// weaknessesFor is the whole judgement, kept in one place so the rules can be read
// together.
func weaknessesFor(ts TrustStatement) []Weakness {
	var out []Weakness

	// 1. No `sub` condition at all. The one unambiguous critical.
	//
	// Exception that must not be missed: a policy may pin the repository through the
	// `repository` claim instead of `sub`. That is narrower than nothing, so it is not
	// this finding — reporting it would be a false positive against a policy that is
	// actually constrained, just not the usual way.
	if len(ts.Subjects) == 0 {
		if pinnedByOtherClaim(ts.Other) {
			// Constrained via repository/repository_owner. Refs are still unbounded,
			// which is a real but lesser problem.
			out = append(out, Weakness{
				Kind: SubjectSpansRefs, Severity: "medium", Sid: ts.Sid,
				Observed: renderConds(ts.Other),
				Detail: "the repository is pinned via a claim other than `sub`, so any ref, " +
					"pull request, or environment of that repository can assume this role",
				Fix: "add a `" + ClaimKey("sub") + "` condition naming the exact ref or environment, " +
					"e.g. StringEquals repo:OWNER/REPO:ref:refs/heads/main",
			})
		} else {
			out = append(out, Weakness{
				Kind: SubjectUnconstrained, Severity: "critical", Sid: ts.Sid,
				Detail: "this statement trusts the GitHub Actions OIDC provider with no `sub` " +
					"condition, so a workflow in ANY repository on GitHub — not only yours — can " +
					"assume this role",
				Fix: "add StringEquals on `" + ClaimKey("sub") + "` naming the exact " +
					"repo:OWNER/REPO:ref:refs/heads/BRANCH (or :environment:NAME) permitted",
			})
		}
	}

	// 2. A `sub` that is present but wildcards. Scope decides severity.
	for _, c := range ts.Subjects {
		if !c.Wildcard() {
			continue // exact, or an asterisk under an operator where it is a literal
		}
		switch scopeOf(c.Value) {
		case scopeAnyRepo:
			out = append(out, Weakness{
				Kind: SubjectSpansRepositories, Severity: "critical", Sid: ts.Sid,
				Observed: c.Op + " " + c.Value,
				Detail: "the `sub` pattern does not pin an owner, so a workflow in any GitHub " +
					"repository can assume this role",
				Fix: "pin the owner and repository: repo:OWNER/REPO:ref:refs/heads/BRANCH",
			})
		case scopeAnyRepoInOwner:
			out = append(out, Weakness{
				Kind: SubjectSpansRepositories, Severity: "high", Sid: ts.Sid,
				Observed: c.Op + " " + c.Value,
				Detail: "the `sub` pattern pins the owner but not the repository, so every " +
					"repository in the organisation — including one any member can create — " +
					"can assume this role",
				Fix: "name the repository explicitly: repo:OWNER/REPO:ref:refs/heads/BRANCH",
			})
		case scopeAnyRef:
			out = append(out, Weakness{
				Kind: SubjectSpansRefs, Severity: "medium", Sid: ts.Sid,
				Observed: c.Op + " " + c.Value,
				Detail: "the repository is pinned but the ref is not, so any branch, tag, pull " +
					"request, or environment of it can assume this role — including a branch " +
					"pushed by a first-time contributor",
				Fix: "pin the ref or environment: repo:OWNER/REPO:ref:refs/heads/main, or " +
					"repo:OWNER/REPO:environment:production",
			})
		}
	}

	// 3. No `aud`. Lesser on its own, and deliberately not folded into the subject
	//    findings — they have different fixes.
	if len(ts.Audiences) == 0 {
		out = append(out, Weakness{
			Kind: AudienceUnconstrained, Severity: "medium", Sid: ts.Sid,
			Detail: "no `aud` condition, so a token minted for a different relying party is accepted",
			Fix:    "add StringEquals on `" + ClaimKey("aud") + "` = " + DefaultAudience,
		})
	}
	return out
}

// pinnedByOtherClaim reports whether a non-`sub` claim constrains WHICH repository is
// trusted. repository_owner alone does not qualify: it still admits every repo in the
// org, which is a different (and still serious) finding, not a reason to stay silent.
func pinnedByOtherClaim(other []Condition) bool {
	for _, c := range other {
		if c.Key == ClaimKey("repository") && !c.Wildcard() {
			return true
		}
	}
	return false
}

// Subject scopes, widest first.
const (
	scopeAnyRepo        = iota // no owner pinned
	scopeAnyRepoInOwner        // owner pinned, repository not
	scopeAnyRef                // owner+repo pinned, ref/environment not
	scopeExact                 // nothing meaningful wildcarded
)

// scopeOf decides how wide a wildcarded `sub` pattern really is, by walking GitHub's
// own subject grammar (repo:OWNER/REPO:<ref|environment|pull_request>) rather than
// counting asterisks.
func scopeOf(pattern string) int {
	p := strings.TrimSpace(pattern)
	if !strings.HasPrefix(p, "repo:") {
		// A bare "*" or any pattern not anchored to the repo: form matches everything
		// GitHub can mint.
		return scopeAnyRepo
	}
	rest := strings.TrimPrefix(p, "repo:")

	owner, after, hasSlash := strings.Cut(rest, "/")
	if strings.Contains(owner, "*") || !hasSlash {
		return scopeAnyRepo
	}
	repo, refPart, hasColon := strings.Cut(after, ":")
	if strings.Contains(repo, "*") {
		return scopeAnyRepoInOwner
	}
	if !hasColon || strings.Contains(refPart, "*") {
		return scopeAnyRef
	}
	return scopeExact
}

// flattenConditions turns a Condition block into (op, key, value) triples, stripping
// the ForAnyValue:/ForAllValues: set-operator prefixes so a wildcard is seen wherever
// it is written.
func flattenConditions(cond map[string]interface{}) []Condition {
	var out []Condition
	for op, kvAny := range cond {
		kv, ok := kvAny.(map[string]interface{})
		if !ok {
			continue
		}
		bare := op
		if i := strings.LastIndex(op, ":"); i >= 0 {
			bare = op[i+1:]
		}
		for key, valAny := range kv {
			for _, v := range condValues(valAny) {
				out = append(out, Condition{Op: bare, Key: key, Value: v})
			}
		}
	}
	return out
}

func condValues(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// likeOp reports whether `*` is a wildcard under this operator. StringEquals and
// friends treat it literally — see the file header.
func likeOp(op string) bool {
	switch strings.ToLower(op) {
	case "stringlike", "stringnotlike", "arnlike":
		return true
	}
	return false
}

// federatedGitHubProviders returns the GitHub OIDC provider ARNs named by a statement's
// Federated principal, or nothing when it names none.
func federatedGitHubProviders(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]interface{}
	if err := jsonUnmarshal(raw, &obj); err != nil {
		return nil
	}
	fed, ok := obj["Federated"]
	if !ok {
		return nil
	}
	var out []string
	for _, p := range condValues(fed) {
		if IsGitHubProvider(p) {
			out = append(out, p)
		}
	}
	return out
}

// otherFederatedProviders returns the non-GitHub federated principals an Allow statement grants role
// assumption to. Restricted to Allow + an assume-role action for the same reason the GitHub path is: a
// Deny naming a provider is the policy working, and reporting it as an unassessed trust would turn
// good hygiene into a warning.
func otherFederatedProviders(st cloudiam.Statement) []string {
	if !strings.EqualFold(st.Effect, "Allow") {
		return nil
	}
	if !hasWebIdentityAction(st.Action) && !hasSAMLAction(st.Action) {
		return nil
	}
	var obj map[string]interface{}
	if err := jsonUnmarshal(st.Principal, &obj); err != nil {
		return nil
	}
	fed, ok := obj["Federated"]
	if !ok {
		return nil
	}
	var out []string
	for _, p := range condValues(fed) {
		if p = strings.TrimSpace(p); p != "" && !IsGitHubProvider(p) {
			out = append(out, p)
		}
	}
	return out
}

func renderConds(cs []Condition) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.Op+" "+c.Key+"="+c.Value)
	}
	return strings.Join(parts, ", ")
}

// jsonUnmarshal is a thin indirection so the import stays local to this file.
func jsonUnmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
