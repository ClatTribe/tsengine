package ghoidc

import (
	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// assume.go answers the transition question — would AWS believe THIS workflow if it
// presented a token to THIS role? — as opposed to trust.go's posture question, which
// asks what the policy permits in general.
//
// It is deliberately a separate answer. "This policy is too broad" and "this specific
// repository can reach this specific role" are different claims with different
// evidence, and collapsing them would let a posture weakness masquerade as a proven
// path.
//
// THE VERDICT IS RUNG-AWARE, NOT THREE-VALUED. A flat
// permitted/blocked/unknown enum cannot express the case this whole package exists to
// surface: a trust that is config-possible but gated on a condition we cannot evaluate
// without the live token. That is neither "blocked" nor a bare "unknown" — it is
// rung 3, needs rung 4 — which is the distinction ADR 0002 was written to preserve.

// Verdict is one assume-role question's answer.
type Verdict struct {
	// Permitted is meaningful ONLY when Decided is true.
	Permitted bool
	// Decided is false when the evidence does not settle it: a condition on a claim we
	// were not given, an operator the evaluator does not implement, an unreadable
	// policy. An undecided verdict is NOT a denial — reading it as one is how a real
	// path gets dismissed.
	Decided bool
	// Rung is the evidence strength, matching the cloud engine's ladder: 1 reasoned
	// (config-possible), 3 symbolic (evaluated against policy, no live touch). A live
	// STS call would be rung 4 and this package never makes one.
	Rung int
	// Subject is the `sub` we tested with, so the answer can be re-derived by hand.
	Subject  string
	Evidence []types.EvidenceItem
}

// CanAssume evaluates whether a workflow context would be permitted to assume the role
// whose trust policy is given. account is the AWS account hosting the OIDC provider.
//
// Grounded (§10): the answer comes from cloudiam evaluating the real trust document
// against the claims GitHub would really mint. Nothing here decides on resemblance,
// and a context too thin to render a subject is refused rather than guessed at.
func CanAssume(trustPolicy []byte, account string, w WorkflowContext) Verdict {
	sub := w.Subject()
	if sub == "" {
		return Verdict{Rung: 1, Subject: "", Evidence: []types.EvidenceItem{{
			Query: "github_oidc_subject(workflow)",
			Observation: "the workflow context names no ref, environment, or pull request, so the " +
				"`sub` claim GitHub would mint is unknown — refusing to guess one",
			AtRung: 1,
		}}}
	}

	doc, err := cloudiam.Parse(trustPolicy)
	if err != nil || doc == nil {
		return Verdict{Rung: 1, Subject: sub, Evidence: []types.EvidenceItem{{
			Query:       "trust_policy(role)",
			Observation: "the role's trust policy could not be parsed — not assessed, NOT assumed safe",
			AtRung:      1,
		}}}
	}

	prov := ProviderARN(account)
	req := cloudiam.Request{
		Principal: prov,
		Action:    "sts:AssumeRoleWithWebIdentity",
		Context:   w.Claims(),
	}
	dec, conditional := cloudiam.Authorize(req, cloudiam.PolicySet{ResourcePolicy: doc, SameAccount: true})

	ev := []types.EvidenceItem{{
		Query:       "sts:AssumeRoleWithWebIdentity(" + prov + " → role) with sub=" + sub,
		Observation: observationFor(dec, conditional),
		AtRung:      3,
	}}

	switch dec {
	case cloudiam.Allow:
		if conditional {
			// Config-possible, but the deciding allow rests on a condition the evaluator
			// could not settle. Reporting this as permitted would be the exact
			// over-claim ADR 0002 forbids.
			return Verdict{Decided: false, Rung: 3, Subject: sub, Evidence: ev}
		}
		return Verdict{Permitted: true, Decided: true, Rung: 3, Subject: sub, Evidence: ev}
	case cloudiam.ExplicitDeny:
		return Verdict{Permitted: false, Decided: true, Rung: 3, Subject: sub, Evidence: ev}
	default:
		// Implicit deny: no statement matched this subject. That IS a decision — it is
		// how a correctly-pinned policy refuses an untrusted repository — and treating
		// it as unknown would make every well-configured role look unassessed.
		return Verdict{Permitted: false, Decided: true, Rung: 3, Subject: sub, Evidence: ev}
	}
}

func observationFor(dec cloudiam.Decision, conditional bool) string {
	switch dec {
	case cloudiam.Allow:
		if conditional {
			return "the trust policy allows this subject, but the deciding statement is gated on a " +
				"condition that cannot be evaluated from the token claims alone — needs live validation (rung 4)"
		}
		return "the trust policy allows this subject: the workflow can assume this role"
	case cloudiam.ExplicitDeny:
		return "an explicit Deny in the trust policy refuses this subject"
	default:
		return "no statement in the trust policy matches this subject: the workflow cannot assume this role"
	}
}
