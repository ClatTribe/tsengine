// Package ghoidc models the GitHub Actions → AWS OIDC identity transition: can a
// workflow in a given repository, on a given ref or environment, assume a given AWS
// role — and if so, was that intended?
//
// WHY THIS IS ITS OWN THING. The engine already reasons about AWS IAM (cloudiam),
// about repositories (the repository asset), and about identity posture (operate).
// What it could not do is JOIN them. A GitHub Actions workflow authenticates to AWS
// with no stored credential at all: it presents a short-lived OIDC token, and the
// role's trust policy decides whether to believe it. That decision is made entirely
// by string conditions on the token's claims, so a single missing condition silently
// grants every repository on the internet the right to assume a production role.
// Nothing in a credential scanner, a CSPM check, or an IAM permission evaluator sees
// it, because there is no credential to find and no permission to over-grant — the
// permissions are fine; the question is WHO gets to use them.
//
// GROUNDING (§10). Two refusals carry this package:
//
//  1. A weakness is reported only from a statement that REALLY grants web-identity
//     assumption to the GitHub issuer — Allow, sts:AssumeRoleWithWebIdentity, and a
//     Federated principal whose ARN names token.actions.githubusercontent.com. A Deny,
//     another provider, or another action is not our finding, and an unparseable
//     policy yields NOTHING rather than a guess.
//
//  2. We never infer severity from what the role can DO, because a trust policy does
//     not contain that. Blast radius is the caller's join (cloudiam + cloudgraph). A
//     package that guessed it would be asserting a consequence it cannot see.
package ghoidc

import (
	"fmt"
	"strings"
)

// Issuer is the GitHub Actions OIDC issuer host. It appears twice in every trust
// policy — as the tail of the Federated provider ARN, and as the prefix of every
// condition key — so it is defined once here.
const Issuer = "token.actions.githubusercontent.com"

// DefaultAudience is the `aud` claim value AWS expects for STS web-identity, and what
// aws-actions/configure-aws-credentials requests by default.
const DefaultAudience = "sts.amazonaws.com"

// ClaimKey renders the IAM condition key for one OIDC claim, e.g.
// ClaimKey("sub") → "token.actions.githubusercontent.com:sub".
func ClaimKey(claim string) string { return Issuer + ":" + claim }

// WorkflowContext is one concrete workflow run's identity — the inputs GitHub uses to
// mint the token's claims. It is a QUESTION ("could this run assume that role?"), not
// an observation, which is why it can be constructed for a run that never happened:
// that is exactly how we ask whether an attacker-controlled branch or a fork's pull
// request would be believed.
type WorkflowContext struct {
	Owner string // "acme"
	Repo  string // "api"

	// Ref is the full git ref, e.g. "refs/heads/main" or "refs/tags/v1.2.3".
	Ref string

	// Environment is the deployment environment the job declares. When set it CHANGES
	// the subject format — GitHub mints an environment subject instead of a ref one —
	// which is the detail that makes a hand-written `sub` matcher wrong more often
	// than not.
	Environment string

	// PullRequest reports that the run was triggered by a pull_request event, whose
	// subject names neither ref nor environment.
	PullRequest bool

	// Audience is the requested `aud`. Empty means DefaultAudience.
	Audience string

	// Actor is the user who triggered the run; JobWorkflowRef identifies the called
	// workflow. Both are optional and only matter when a trust policy conditions on
	// them (rare, but the stronger patterns do).
	Actor          string
	JobWorkflowRef string
}

// Repository is the "owner/repo" claim value.
func (w WorkflowContext) Repository() string { return w.Owner + "/" + w.Repo }

// Subject renders the `sub` claim exactly as GitHub mints it. Getting this string
// wrong is the whole ballgame — a matcher tested against the wrong format will pass
// its own tests and misjudge every real policy — so the four shapes are spelled out
// rather than composed:
//
//	repo:OWNER/REPO:environment:NAME     (a job declaring an environment)
//	repo:OWNER/REPO:pull_request         (a pull_request-triggered run)
//	repo:OWNER/REPO:ref:refs/heads/main  (a branch)
//	repo:OWNER/REPO:ref:refs/tags/v1     (a tag)
//
// Precedence is environment → pull_request → ref, which is GitHub's own order: a job
// with an environment gets the environment subject even on a branch push.
func (w WorkflowContext) Subject() string {
	base := "repo:" + w.Repository()
	switch {
	case w.Environment != "":
		return base + ":environment:" + w.Environment
	case w.PullRequest:
		return base + ":pull_request"
	case w.Ref != "":
		return base + ":ref:" + w.Ref
	default:
		// No ref, no environment, not a PR: we cannot render a subject we would stand
		// behind, so we render none. A caller must treat "" as unanswerable rather
		// than as a subject that matches nothing.
		return ""
	}
}

// Claims renders the IAM request-context map for this run: every claim we can state,
// keyed the way a trust policy conditions on it. Claims we do not know are OMITTED
// rather than blanked, because cloudiam treats an absent key as "undecided" and an
// empty one as "the empty string" — and those must not be confused.
func (w WorkflowContext) Claims() map[string]string {
	aud := w.Audience
	if aud == "" {
		aud = DefaultAudience
	}
	c := map[string]string{
		ClaimKey("aud"):              aud,
		ClaimKey("repository"):       w.Repository(),
		ClaimKey("repository_owner"): w.Owner,
	}
	if sub := w.Subject(); sub != "" {
		c[ClaimKey("sub")] = sub
	}
	if w.Ref != "" {
		c[ClaimKey("ref")] = w.Ref
		c[ClaimKey("ref_type")] = refType(w.Ref)
	}
	if w.Environment != "" {
		c[ClaimKey("environment")] = w.Environment
	}
	if w.Actor != "" {
		c[ClaimKey("actor")] = w.Actor
	}
	if w.JobWorkflowRef != "" {
		c[ClaimKey("job_workflow_ref")] = w.JobWorkflowRef
	}
	if w.PullRequest {
		c[ClaimKey("event_name")] = "pull_request"
	}
	return c
}

func refType(ref string) string {
	switch {
	case strings.HasPrefix(ref, "refs/heads/"):
		return "branch"
	case strings.HasPrefix(ref, "refs/tags/"):
		return "tag"
	default:
		return ""
	}
}

// ProviderARN renders the OIDC provider ARN for an account — the Federated principal
// a GitHub-trusting role names.
func ProviderARN(account string) string {
	return fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", account, Issuer)
}

// IsGitHubProvider reports whether an ARN is the GitHub Actions OIDC provider. Matched
// on the issuer host rather than the whole ARN so it holds across accounts and
// partitions (aws / aws-us-gov / aws-cn).
func IsGitHubProvider(arn string) bool {
	return strings.HasSuffix(strings.TrimSuffix(arn, "/"), "/"+Issuer)
}
