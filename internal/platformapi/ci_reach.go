package platformapi

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/internal/ciproof"
	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ci_reach.go joins the two halves of a CI-identity attack on a real tenant's inventory: ghoidc says
// a role's trust is over-broad, the provider dry-run says what that role can then reach.
//
// WHY THE JOIN CHANGES THE FINDING RATHER THAN ADDING ONE. "This role's trust policy is
// unconditioned" is a posture note a reader may reasonably defer — plenty of roles are broadly
// trusted and hold nothing. "This role's trust policy is unconditioned AND the provider confirms it
// can read your customer-data bucket" is the same defect with a blast radius attached, and it is the
// second half that decides whether anyone acts this week. Emitting a separate finding would split one
// fact across two rows and leave the original still reading as deferrable.
//
// # WHY AN ARBITRARY THIRD-PARTY REPOSITORY IS THE RIGHT ACTOR TO TEST WITH
//
// The platform does not know which workflows a customer runs, and asking "can acme/web assume the
// role acme/web is meant to assume" answers itself. The question worth putting to a trust policy is
// whether it admits someone it should not, so the probe subject is a repository the customer plainly
// does not control.
//
// That choice also does the budget gating for free, which is why it beats probing every role. A
// correctly-scoped policy REFUSES at the trust half, and ciproof.Prove then spends NO provider call —
// so only genuinely over-broad roles ever reach the simulator, and read-only is not free (every call
// writes to the customer's audit trail and consumes their quota, ADR 0024 C10).
//
// THE HONEST LIMIT, stated because it is easy to over-read: this tests ONE hypothetical actor. A
// policy that admits a narrower-but-still-wrong set — a partner's repository, a fork — refuses this
// probe and is ghoidc.Assess's job, not this one. A clean result here is not a statement that the
// trust is correctly scoped.

// probeRepo is the actor tested against every federated trust policy: a repository under an owner no
// customer controls. Using a real-looking slug would risk naming someone's actual repository in a
// finding, so this one is reserved by construction — `.invalid` is the RFC 2606 reserved TLD and can
// never be a GitHub owner.
const probeRepoOwner = "third-party.invalid"

// reachBudget bounds live provider calls per ingest. Each is read-only but not free (C10), and an
// estate with many over-broad roles and many crown jewels multiplies quickly.
const reachBudget = 20

// annotateCIReach upgrades ghoidc trust-weakness findings with what the provider says the role can
// actually reach. Returns the findings unchanged when there is nothing to ask or nothing to ask with.
func annotateCIReach(ctx context.Context, raw awsinventory.RawAWS, findings []types.Finding, prober cloudagent.ExploitProber) []types.Finding {
	if prober == nil || len(findings) == 0 {
		return findings
	}
	targets := sensitiveTargets(raw)
	if len(targets) == 0 {
		// No declared crown jewel to reach. Probing every bucket instead would spend the budget to
		// produce noise, and inferring sensitivity from a bucket NAME is the guess dataplatform
		// already refuses to make.
		return findings
	}
	byARN := map[string]ghoidc.Role{}
	for _, r := range raw.Roles {
		if strings.TrimSpace(r.TrustPolicyJSON) != "" {
			byARN[r.ARN] = ghoidc.Role{ARN: r.ARN, Name: r.Name, Account: raw.AccountID,
				TrustPolicy: r.TrustPolicyJSON, Privileged: r.Admin}
		}
	}

	spent := 0
	out := make([]types.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if spent >= reachBudget {
			break
		}
		if !strings.HasPrefix(out[i].RuleID, "ghoidc::") {
			continue
		}
		role, ok := byARN[out[i].Endpoint]
		if !ok {
			continue
		}
		for _, t := range targets {
			if spent >= reachBudget {
				break
			}
			c := ciproof.Prove(ctx, role, outsiderWorkflow(), t, prober)
			// Only an END-TO-END authorization upgrades the finding. A trust refusal means the policy
			// is not over-broad in the way tested; a permission refusal or an unknown proves nothing
			// about reach. None of them may WEAKEN the existing weakness finding either — ghoidc found
			// it by reading the policy, and this probe was never evidence against that.
			if c.Status != ciproof.StatusAuthorized {
				if c.Permission != nil && c.Permission.Asked {
					spent++
				}
				continue
			}
			spent++
			out[i].Description += "\n\n" + c.Summary
			// A trust weakness that demonstrably reaches declared-sensitive data is not the same
			// finding as one that reaches nothing, and severity is what decides the queue order.
			// Raises only — never lowers what ghoidc already judged.
			if out[i].Severity.Rank() < types.SeverityCritical.Rank() {
				out[i].Severity = types.SeverityCritical
			}
			break // one proven reach is enough to make the point; the rest is budget
		}
	}
	return out
}

// sensitiveTargets are the crown jewels worth asking about, with the action a provider can actually
// answer for.
//
// Sensitive is DECLARED by the collector, never inferred from a bucket name — the same refusal
// dataplatform makes, and the reason a table called "customers" is not evidence. The action is
// s3:GetObject because that is the read verb for an S3 object, a fact about AWS rather than a guess;
// a resource kind with no single canonical read gets no target rather than an invented one.
func sensitiveTargets(raw awsinventory.RawAWS) []ciproof.Target {
	var out []ciproof.Target
	for _, b := range raw.Buckets {
		if !b.Sensitive {
			continue
		}
		arn := b.ARN
		if strings.TrimSpace(arn) == "" {
			if strings.TrimSpace(b.Name) == "" {
				continue
			}
			arn = "arn:aws:s3:::" + b.Name
		}
		out = append(out, ciproof.Target{Action: "s3:GetObject", Resource: strings.TrimSuffix(arn, "/*") + "/*"})
	}
	return out
}

// outsiderWorkflow is the hypothetical actor: a workflow in a repository the customer does not own.
func outsiderWorkflow() ghoidc.WorkflowContext {
	return ghoidc.WorkflowContext{Owner: probeRepoOwner, Repo: "any", Ref: "refs/heads/main"}
}

// rawAWSOrEmpty decodes the posted inventory for the reach join. A body that does not parse yields an
// empty struct rather than an error: the caller has already reported the parse failure, and the join
// then simply has nothing to ask about.
func rawAWSOrEmpty(body []byte) awsinventory.RawAWS {
	var raw awsinventory.RawAWS
	_ = json.Unmarshal(body, &raw)
	return raw
}
