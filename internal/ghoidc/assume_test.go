package ghoidc

import "testing"

const acct = "123456789012"

// A correctly pinned production role: acme/api on main only.
var pinned = trust(`,"Condition":{"StringEquals":{
   "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
   "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`)

func TestCanAssume_TrustedWorkflowIsPermitted(t *testing.T) {
	v := CanAssume(pinned, acct, WorkflowContext{Owner: "acme", Repo: "api", Ref: "refs/heads/main"})
	if !v.Decided || !v.Permitted {
		t.Fatalf("the pinned workflow must be permitted, got %+v", v)
	}
	if v.Rung != 3 {
		t.Fatalf("a policy-evaluated answer is rung 3, got %d", v.Rung)
	}
}

// The whole point: a DIFFERENT repository presenting a token is refused, and that
// refusal is DECIDED — not unknown. A correctly configured role must not read as
// unassessed, or every good policy would look like a gap.
func TestCanAssume_UntrustedRepositoryIsDecidedNotUnknown(t *testing.T) {
	v := CanAssume(pinned, acct, WorkflowContext{Owner: "attacker", Repo: "evil", Ref: "refs/heads/main"})
	if !v.Decided {
		t.Fatal("an implicit deny IS a decision — a correctly-pinned policy must not read as unassessed")
	}
	if v.Permitted {
		t.Fatal("an untrusted repository must not be permitted")
	}
}

// A feature branch of the RIGHT repo is still refused when the ref is pinned.
func TestCanAssume_WrongRefOnTheRightRepoIsRefused(t *testing.T) {
	v := CanAssume(pinned, acct, WorkflowContext{Owner: "acme", Repo: "api", Ref: "refs/heads/feature-x"})
	if v.Permitted {
		t.Fatal("a non-main branch must not assume a main-pinned role")
	}
}

// The subject-format trap: a job declaring an environment gets an ENVIRONMENT subject,
// not a ref subject — so a ref-pinned policy refuses it. A matcher built on the wrong
// format would wrongly permit this.
func TestCanAssume_EnvironmentSubjectDoesNotMatchARefPin(t *testing.T) {
	v := CanAssume(pinned, acct, WorkflowContext{
		Owner: "acme", Repo: "api", Ref: "refs/heads/main", Environment: "production"})
	if v.Subject != "repo:acme/api:environment:production" {
		t.Fatalf("environment takes precedence over ref in GitHub's subject format, got %q", v.Subject)
	}
	if v.Permitted {
		t.Fatal("a ref-pinned trust must refuse an environment subject")
	}
}

// The finding that pays for the package: an unconstrained trust lets a repository
// nobody has ever heard of assume the role.
func TestCanAssume_UnconstrainedTrustPermitsAnyRepository(t *testing.T) {
	open := trust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`)
	v := CanAssume(open, acct, WorkflowContext{Owner: "some-stranger", Repo: "anything", Ref: "refs/heads/main"})
	if !v.Decided || !v.Permitted {
		t.Fatalf("a trust policy with no sub condition permits ANY repository, got %+v", v)
	}
}

func TestCanAssume_WildcardOrgTrustPermitsASiblingRepository(t *testing.T) {
	orgWide := trust(`,"Condition":{
       "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
       "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`)
	v := CanAssume(orgWide, acct, WorkflowContext{Owner: "acme", Repo: "someones-scratch-repo", Ref: "refs/heads/main"})
	if !v.Permitted {
		t.Fatal("repo:acme/* trusts every repository in the org, including a scratch one")
	}
	// ...but not another org.
	other := CanAssume(orgWide, acct, WorkflowContext{Owner: "notacme", Repo: "api", Ref: "refs/heads/main"})
	if other.Permitted {
		t.Fatal("repo:acme/* must not trust a different owner")
	}
}

// An audience mismatch is refused: that is what the aud condition is for.
func TestCanAssume_WrongAudienceIsRefused(t *testing.T) {
	v := CanAssume(pinned, acct, WorkflowContext{
		Owner: "acme", Repo: "api", Ref: "refs/heads/main", Audience: "https://example.com"})
	if v.Permitted {
		t.Fatal("a token minted for a different audience must be refused")
	}
}

// Refusals: too-thin context, and an unreadable policy. Neither may answer "permitted",
// and neither may answer a confident "denied" either.
func TestCanAssume_RefusesRatherThanGuesses(t *testing.T) {
	thin := CanAssume(pinned, acct, WorkflowContext{Owner: "acme", Repo: "api"})
	if thin.Decided || thin.Permitted {
		t.Fatal("a context with no ref/environment/PR cannot render a subject — refuse, do not guess")
	}
	if thin.Subject != "" {
		t.Fatal("no subject should be rendered from an unanswerable context")
	}

	broken := CanAssume([]byte("<<<not json"), acct, WorkflowContext{Owner: "a", Repo: "b", Ref: "refs/heads/main"})
	if broken.Decided || broken.Permitted {
		t.Fatal("an unparseable trust policy is not assessed, and certainly not safe")
	}
}

// Evidence must be present and cite the subject, so a human can re-derive the verdict.
func TestCanAssume_EvidenceCitesTheSubjectTested(t *testing.T) {
	v := CanAssume(pinned, acct, WorkflowContext{Owner: "acme", Repo: "api", Ref: "refs/heads/main"})
	if len(v.Evidence) == 0 {
		t.Fatal("a verdict with no evidence is an assertion")
	}
	if v.Evidence[0].AtRung != 3 {
		t.Fatalf("policy-evaluated evidence is rung 3, got %d", v.Evidence[0].AtRung)
	}
}

func TestSubject_AllFourGitHubFormats(t *testing.T) {
	for _, tc := range []struct {
		w    WorkflowContext
		want string
	}{
		{WorkflowContext{Owner: "a", Repo: "b", Ref: "refs/heads/main"}, "repo:a/b:ref:refs/heads/main"},
		{WorkflowContext{Owner: "a", Repo: "b", Ref: "refs/tags/v1"}, "repo:a/b:ref:refs/tags/v1"},
		{WorkflowContext{Owner: "a", Repo: "b", PullRequest: true}, "repo:a/b:pull_request"},
		{WorkflowContext{Owner: "a", Repo: "b", Environment: "prod"}, "repo:a/b:environment:prod"},
	} {
		if got := tc.w.Subject(); got != tc.want {
			t.Errorf("Subject() = %q, want %q", got, tc.want)
		}
	}
}

// Claims must OMIT what is unknown rather than blank it: cloudiam treats an absent key
// as undecided and an empty one as the empty string, and confusing those flips verdicts.
func TestClaims_OmitsUnknownRatherThanBlanking(t *testing.T) {
	c := WorkflowContext{Owner: "a", Repo: "b", Ref: "refs/heads/main"}.Claims()
	if _, present := c[ClaimKey("environment")]; present {
		t.Fatal("an unset environment must be absent, not empty — absent means undecided")
	}
	if c[ClaimKey("ref_type")] != "branch" {
		t.Fatalf("ref_type should be derived from the ref, got %q", c[ClaimKey("ref_type")])
	}
}
