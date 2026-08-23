// Package ciproof chains the two halves of a CI-identity attack into one claim: a workflow in some
// repository can assume a cloud role (the TRUST half), and that role can then reach something worth
// reaching (the PERMISSION half).
//
// WHY THIS IS THE DIFFERENTIATED CLAIM. Generic IAM simulation answers "can this principal do that?"
// — useful, and what the autonomous-pentest incumbents ship. It does not answer the question a CI
// federation actually raises, which is WHO gets to be that principal. A federated role has no stored
// credential for a scanner to find and no over-grant for an evaluator to flag: the permissions are
// often exactly right, and the whole risk lives in a string condition on a token claim. So the two
// halves are individually unremarkable and jointly the finding — an unconditioned trust policy is
// "fine, the role is narrow" and a broad role is "fine, only our CI can assume it", right up until
// they are the same role.
//
// Each half already exists and neither knew about the other: ghoidc/gcpwif/samltrust decide the trust
// question and say plainly that a trust policy does not tell you what the role can DO, while the
// provider dry-run (ADR 0024 P1) answers exactly that and has no idea who may assume the principal
// it is asked about. This package is the join, and nothing more — it computes no new facts.
//
// # THE TWO HALVES ARE DIFFERENT KINDS OF EVIDENCE AND MUST NOT BE FLATTENED
//
// The trust half is decided SYMBOLICALLY: the real policy document evaluated against the claims the
// issuer would really mint, with no live call (ghoidc's rung 3). The permission half is decided by
// the PROVIDER's own policy simulator — a live read, and authorization only, never exploitability
// (ADR 0024 C1). Collapsing them into one word would let the weaker half inherit the stronger half's
// authority, which is the defect this ADR has now had to correct three times.
package ciproof

import (
	"context"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

// Status is the chain's standing end to end.
type Status string

const (
	// StatusAuthorized — trust admits the workflow AND the provider allows the role the action. The
	// strongest claim available without exploiting anything: an identity outside the account can
	// legitimately obtain this access.
	StatusAuthorized Status = "authorized_end_to_end"
	// StatusRefusedAtTrust — the trust policy does not admit this workflow. Authoritative for the
	// subject tested; it does not mean no OTHER workflow can.
	StatusRefusedAtTrust Status = "refused_at_trust"
	// StatusRefusedAtPermission — trust admits the workflow, but the provider refuses the role the
	// action. The federation is real; this particular reach is not.
	StatusRefusedAtPermission Status = "refused_at_permission"
	// StatusUndetermined — one half could not be decided. NOT a denial (ghoidc is explicit that an
	// undecided verdict read as a denial is how a real path gets dismissed).
	StatusUndetermined Status = "undetermined"
)

// TrustLeg is the "who may become this principal" half.
type TrustLeg struct {
	// Subject is the token subject actually tested, so the answer can be re-derived by hand.
	Subject string `json:"subject,omitempty"`
	// Repository is the repo whose workflow we tested with.
	Repository string `json:"repository,omitempty"`
	// AdmitsPattern is set when the policy's own `sub` condition WILDCARDS — meaning the role admits
	// more than the one workflow we tested, and naming only that workflow would understate the
	// finding by an unbounded factor.
	//
	// The wildcard lives in the POLICY, not in the subject we tested with, and getting that backwards
	// is easy: the tested subject is always concrete, so checking IT for an asterisk finds nothing and
	// silently reports "only acme/web can assume this role" about a policy that admits the whole org.
	// ghoidc.Condition.Wildcard() is reused rather than re-implemented because it already encodes the
	// operator distinction that makes the answer correct — an asterisk under StringEquals is a
	// LITERAL, so `StringEquals sub=repo:acme/*` matches a repository named "*", i.e. nothing.
	AdmitsPattern string `json:"admits_pattern,omitempty"`
	Permitted     bool   `json:"permitted"`
	Decided       bool   `json:"decided"`
	// Rung mirrors ghoidc's ladder: 3 = evaluated symbolically against the real policy, no live call.
	Rung int    `json:"rung,omitempty"`
	Why  string `json:"why,omitempty"`
}

// PermissionLeg is the "what can that principal then reach" half.
type PermissionLeg struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	// Verdict is the provider's own answer, stringified: ALLOW / DENY / UNKNOWN.
	Verdict string `json:"verdict"`
	Detail  string `json:"detail,omitempty"`
	Why     string `json:"why,omitempty"`
	// Asked is false when we never put the question — because the trust half already closed the
	// chain, so spending a live provider call (and a line in the customer's audit trail) would buy
	// nothing (ADR 0024 C10).
	Asked bool `json:"asked"`
}

// Chain is one end-to-end CI-identity claim.
type Chain struct {
	RoleARN string   `json:"role_arn"`
	Trust   TrustLeg `json:"trust"`
	// Permission is nil when the trust half closed the chain before we asked.
	Permission *PermissionLeg `json:"permission,omitempty"`
	Status     Status         `json:"status"`
	// Summary is the one sentence a human reads. It always names which half is doing the work, so a
	// half-established chain can never be skimmed as a complete one.
	Summary string `json:"summary"`
}

// Target is what a role might reach, supplied by the caller from the graph. The action is required
// because "can this role reach that bucket" is not a question a provider can answer — a provider
// answers about an ACTION on a resource, and inventing a plausible one would fabricate the question.
type Target struct {
	Action   string
	Resource string
}

// Prove chains one role's trust policy against one target.
//
// prober may be nil, in which case the permission half is honestly UNASKED rather than assumed either
// way — the same degradation the cloud agent makes when no probe path is configured.
func Prove(ctx context.Context, role ghoidc.Role, w ghoidc.WorkflowContext, t Target, prober cloudagent.ExploitProber) Chain {
	c := Chain{RoleARN: role.ARN}

	v := ghoidc.CanAssume([]byte(role.TrustPolicy), role.Account, w)
	c.Trust = TrustLeg{
		Subject: v.Subject, Repository: ghoidc.RepositoryOfSubject(v.Subject),
		AdmitsPattern: admittedPattern([]byte(role.TrustPolicy)),
		Permitted:     v.Permitted, Decided: v.Decided, Rung: v.Rung,
	}

	switch {
	case !v.Decided:
		// An undecided trust verdict is NOT a denial. Asking the provider anyway would produce a
		// permission answer with nothing to attach it to, and a reader would attach it anyway.
		c.Trust.Why = "the trust policy did not settle whether this workflow is admitted"
		c.Status = StatusUndetermined
		c.Summary = "Undetermined: we could not decide whether " + subjectLabel(c.Trust) +
			" may assume " + role.ARN + ", so nothing downstream of that is established either."
		return c
	case !v.Permitted:
		// Closed at hop 1. Do NOT spend a live provider call: it is read-only but not free — it
		// writes to the customer's audit trail and consumes their quota (ADR 0024 C10).
		c.Status = StatusRefusedAtTrust
		c.Summary = "No chain: " + role.ARN + " does not admit " + subjectLabel(c.Trust) +
			". That is authoritative for this subject only — it does not mean no other workflow can " +
			"assume the role."
		return c
	}

	if prober == nil {
		c.Permission = &PermissionLeg{Action: t.Action, Resource: t.Resource, Verdict: "UNKNOWN", Asked: false,
			Why: "no provider dry-run was configured, so what this role can reach was never established"}
		c.Status = StatusUndetermined
		c.Summary = "Partly established: " + subjectLabel(c.Trust) + " may assume " + role.ARN +
			", but what that role can then reach was never checked with the provider."
		return c
	}

	res, err := prober.CanPerform(ctx, role.ARN, t.Action, t.Resource)
	leg := &PermissionLeg{Action: t.Action, Resource: t.Resource, Verdict: res.Verdict.String(),
		Detail: res.Detail, Why: res.Why, Asked: true}
	if err != nil && leg.Why == "" {
		leg.Why = err.Error()
	}
	c.Permission = leg

	switch res.Verdict {
	case cloudagent.VerdictAllow:
		c.Status = StatusAuthorized
		c.Summary = subjectLabel(c.Trust) + " may assume " + role.ARN + " (the trust policy admits it), " +
			"and the cloud provider confirms that role may " + t.Action + " on " + t.Resource + ". " +
			"That is authorization end to end, not a demonstrated exploit: nothing was run and no " +
			"access was used."
	case cloudagent.VerdictDeny:
		c.Status = StatusRefusedAtPermission
		c.Summary = subjectLabel(c.Trust) + " may assume " + role.ARN + ", but the provider refuses " +
			"that role " + t.Action + " on " + t.Resource + ". The federation is real; this particular " +
			"reach is not."
	default:
		c.Status = StatusUndetermined
		c.Summary = "Partly established: " + subjectLabel(c.Trust) + " may assume " + role.ARN +
			", but the provider could not say whether that role may " + t.Action + " on " + t.Resource +
			reasonSuffix(leg.Why) + "."
	}
	return c
}

// admittedPattern returns the policy's own wildcarding `sub` condition, when it has one.
//
// This is the breadth of the trust, which is a different question from the identity we tested with
// and the one a reader most needs answered: "acme/web can reach production" and "any repository in
// acme can reach production" are the same chain with wildly different blast radius.
//
// An unparseable policy yields nothing rather than a guess — CanAssume will already have returned
// undecided for it, so nothing downstream depends on this being right in that case.
func admittedPattern(trustPolicy []byte) string {
	a := ghoidc.Analyze(trustPolicy)
	if !a.Parsed || !a.TrustsGitHub {
		return ""
	}
	for _, st := range a.Statements {
		for _, cond := range st.Subjects {
			if cond.Wildcard() {
				return cond.Value
			}
		}
	}
	return ""
}

// subjectLabel names the actor as precisely as the evidence allows and NO MORE PRECISELY.
//
// When the policy wildcards, naming only the workflow we happened to test would tell a reader that
// one repository can reach this role when the truth is that a whole class can — an understatement of
// the finding by an unbounded factor, and the more dangerous direction here, since the reader's next
// move is deciding how urgently to re-scope the trust.
func subjectLabel(t TrustLeg) string {
	switch {
	case t.AdmitsPattern != "" && t.Repository != "":
		return "a workflow in " + t.Repository + " — and any other matching " + t.AdmitsPattern
	case t.AdmitsPattern != "":
		return "any workflow whose token subject matches " + t.AdmitsPattern
	case t.Repository != "":
		return "a workflow in " + t.Repository
	case t.Subject != "":
		return "a workflow whose token subject matches " + t.Subject
	}
	return "a federated workflow"
}

func reasonSuffix(why string) string {
	if strings.TrimSpace(why) == "" {
		return ""
	}
	return " (" + why + ")"
}
