package cloudprobe

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
)

// aws.go is the LIVE AWS adapter for the provider dry-run — ADR 0024 P1a, the first rung of the
// verification ladder that anything outside a test can actually reach.
//
// It calls iam:SimulatePrincipalPolicy, which evaluates a (principal, action, resource) tuple against
// the principal's real attached policies, its permissions boundary and the account's SCPs, and returns
// AWS's own decision WITHOUT performing the action. Read-only by construction: the API has no side
// effect on account state.
//
// # WHAT AN ALLOW HERE DOES AND DOES NOT MEAN
//
// It means the AUTHORIZATION is confirmed for that tuple at that moment. It does NOT mean the path is
// exploitable (ADR 0024 C1), and AWS says so itself: the simulator does not automatically retrieve
// resource-based policies, does not support every policy type, and behaves differently from live
// evaluation for role chaining, VPC endpoint policies and multiple resource policies. Everything the
// simulator could not model has to arrive as UNKNOWN rather than as a decision, which is why
// Decision.Known exists and why the mapping below is deliberately conservative in one direction only.
//
// # THE ONE PLACE THIS COULD LIE, AND WHY IT DOES NOT
//
// SimulatePrincipalPolicy returns a per-action EvalDecision string. Only "allowed" is an allow;
// "explicitDeny" and "implicitDeny" are both real, decided DENIES — an implicit deny is how a
// correctly-scoped policy refuses a stranger, so collapsing it into "we don't know" would discard the
// strongest negative evidence this system can obtain (C9, which had to be fixed once already because
// denials were being dropped entirely). Anything else AWS ever returns is UNKNOWN and says so, rather
// than being read as either answer.
//
// A MISSING CONTEXT KEY IS NOT A DENY. When a policy's conditions reference context we did not supply,
// AWS reports the evaluation with MissingContextValues populated. The decision it returns in that case
// is not a statement about the real world — it is a statement about the request we were able to
// describe. Treating that as an authoritative deny would close a live attack path on our own missing
// input, so those come back UNKNOWN with the missing keys named.

// awsIAMAPI is the slice of the IAM client this adapter uses — an interface so the mapping above is
// tested against real API shapes without an AWS account.
type awsIAMAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, in *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// AWSSimulator evaluates tuples against a customer account through a scoped read-only role.
type AWSSimulator struct {
	Region     string
	RoleARN    string
	ExternalID string

	// newAPI is injectable so tests exercise the decision mapping without AWS.
	newAPI func(ctx context.Context) (awsIAMAPI, error)
}

// NewAWSSimulator builds a simulator against the customer's scoped read-only cross-account role — the
// same role awsfetch already uses, because SimulatePrincipalPolicy is a read.
func NewAWSSimulator(region, roleARN, externalID string) *AWSSimulator {
	return &AWSSimulator{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

func (s *AWSSimulator) api(ctx context.Context) (awsIAMAPI, error) {
	if s.newAPI != nil {
		return s.newAPI(ctx)
	}
	cfg, err := awsfetch.AssumeRoleConfig(ctx, s.Region, s.RoleARN, s.ExternalID)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}

// Simulate asks AWS's own policy engine whether principal may perform action on resource.
func (s *AWSSimulator) Simulate(ctx context.Context, principal, action, resource string) (Decision, error) {
	// Refuse an under-specified tuple rather than sending it. AWS would answer SOMETHING for a call
	// with an empty resource — evaluating against "*" — and that answer would be about a different
	// question than the one the caller asked, while arriving with the authority of a provider verdict.
	if strings.TrimSpace(principal) == "" || strings.TrimSpace(action) == "" {
		return Decision{Known: false, Why: "principal and action are required to simulate a tuple"}, nil
	}
	api, err := s.api(ctx)
	if err != nil {
		return Decision{Known: false, Why: "could not reach the account: " + err.Error()}, err
	}
	in := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principal),
		ActionNames:     []string{action},
	}
	if r := strings.TrimSpace(resource); r != "" {
		in.ResourceArns = []string{r}
	}
	out, err := api.SimulatePrincipalPolicy(ctx, in)
	if err != nil {
		// An API failure is UNKNOWN, never a deny. A throttle, an expired session or a role without
		// iam:SimulatePrincipalPolicy would otherwise silently close every path it touched.
		return Decision{Known: false, Why: "simulate call failed: " + err.Error()}, err
	}
	return decisionFrom(out, action), nil
}

// decisionFrom maps AWS's evaluation results onto our three-valued answer.
func decisionFrom(out *iam.SimulatePrincipalPolicyOutput, action string) Decision {
	if out == nil || len(out.EvaluationResults) == 0 {
		return Decision{Known: false, Why: "the simulator returned no evaluation for " + action}
	}
	// One action in, so one result out; scan rather than index [0] so an unexpected multi-result
	// response cannot be read as an answer about a different action than the one we asked.
	for _, r := range out.EvaluationResults {
		if r.EvalActionName == nil || *r.EvalActionName != action {
			continue
		}
		if len(r.MissingContextValues) > 0 {
			return Decision{
				Known: false,
				Why: "the policy's conditions need context we did not supply (" +
					strings.Join(r.MissingContextValues, ", ") + "), so this decision describes our " +
					"request rather than the real one",
			}
		}
		switch r.EvalDecision {
		case iamtypes.PolicyEvaluationDecisionTypeAllowed:
			return Decision{Allowed: true, Known: true, Detail: matchedDetail(r, "allowed")}
		case iamtypes.PolicyEvaluationDecisionTypeExplicitDeny:
			return Decision{Allowed: false, Known: true, Detail: matchedDetail(r, "explicit deny")}
		case iamtypes.PolicyEvaluationDecisionTypeImplicitDeny:
			// A real, decided refusal: no statement grants it. This is how a correctly-scoped policy
			// refuses, and it is evidence, not an absence of one.
			return Decision{Allowed: false, Known: true, Detail: matchedDetail(r, "implicit deny — no statement grants it")}
		default:
			return Decision{Known: false, Why: fmt.Sprintf("unrecognised evaluation decision %q", r.EvalDecision)}
		}
	}
	return Decision{Known: false, Why: "the simulator returned no evaluation for " + action}
}

// matchedDetail names the statements AWS says decided it, so a verdict can be audited rather than
// taken on trust. Falls back to the bare decision when AWS names nothing.
func matchedDetail(r iamtypes.EvaluationResult, decision string) string {
	var srcs []string
	for _, m := range r.MatchedStatements {
		if m.SourcePolicyId != nil && *m.SourcePolicyId != "" {
			srcs = append(srcs, *m.SourcePolicyId)
		}
	}
	if len(srcs) == 0 {
		return decision
	}
	return decision + " (" + strings.Join(srcs, ", ") + ")"
}

// Describe is the coverage line that rides with every probe report. It states the limits of the
// method rather than only the provider's name: a reader who sees "provider-confirmed" needs the same
// sentence AWS puts in its own documentation.
func (s *AWSSimulator) Describe() string {
	where := s.RoleARN
	if where == "" {
		where = "the ambient AWS credentials"
	}
	return "AWS iam:SimulatePrincipalPolicy via " + where + " — evaluates identity policies, " +
		"permissions boundaries and SCPs; does NOT auto-retrieve resource-based policies and does not " +
		"model role chaining or VPC endpoint policies, so those arrive as unknown rather than as a decision"
}

var _ Simulator = (*AWSSimulator)(nil)
