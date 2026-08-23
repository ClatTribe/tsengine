package cloudprobe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeIAM struct {
	out *iam.SimulatePrincipalPolicyOutput
	err error
	in  *iam.SimulatePrincipalPolicyInput
}

func (f *fakeIAM) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.in = in
	return f.out, f.err
}

func simWith(f *fakeIAM) *AWSSimulator {
	s := NewAWSSimulator("us-east-1", "arn:aws:iam::111122223333:role/tsengine-read", "ext")
	s.newAPI = func(context.Context) (awsIAMAPI, error) { return f, nil }
	return s
}

func evalResult(action string, d iamtypes.PolicyEvaluationDecisionType) *iam.SimulatePrincipalPolicyOutput {
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{{
		EvalActionName: aws.String(action), EvalDecision: d,
	}}}
}

// The three-valued mapping IS the grounding. Each row is a different claim about the world and they
// must never collapse into each other.
func TestAWSSimulator_DecisionMapping(t *testing.T) {
	const action = "s3:GetObject"
	for _, tc := range []struct {
		name        string
		out         *iam.SimulatePrincipalPolicyOutput
		wantAllowed bool
		wantKnown   bool
	}{
		{"allowed is an allow", evalResult(action, iamtypes.PolicyEvaluationDecisionTypeAllowed), true, true},
		// Both denies are DECIDED answers. An implicit deny is how a correctly-scoped policy refuses a
		// stranger; reading it as "unknown" would throw away the strongest negative evidence available
		// (ADR 0024 C9, which had to be fixed once already because denials were dropped entirely).
		{"explicit deny is a decided deny", evalResult(action, iamtypes.PolicyEvaluationDecisionTypeExplicitDeny), false, true},
		{"implicit deny is a decided deny", evalResult(action, iamtypes.PolicyEvaluationDecisionTypeImplicitDeny), false, true},
		{"an empty response decides nothing", &iam.SimulatePrincipalPolicyOutput{}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := simWith(&fakeIAM{out: tc.out}).Simulate(context.Background(), "arn:aws:iam::1:role/app", action, "arn:aws:s3:::crown/*")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Known != tc.wantKnown || d.Allowed != tc.wantAllowed {
				t.Fatalf("got allowed=%v known=%v, want allowed=%v known=%v (%s)",
					d.Allowed, d.Known, tc.wantAllowed, tc.wantKnown, d.Why)
			}
		})
	}
}

// A missing context value means AWS evaluated the request WE could describe, not the real one. Reading
// that as an authoritative deny would close a live attack path on our own missing input.
func TestAWSSimulator_MissingContextIsUnknownNotDeny(t *testing.T) {
	out := evalResult("sts:AssumeRole", iamtypes.PolicyEvaluationDecisionTypeImplicitDeny)
	out.EvaluationResults[0].MissingContextValues = []string{"aws:MultiFactorAuthPresent", "sts:ExternalId"}

	d, _ := simWith(&fakeIAM{out: out}).Simulate(context.Background(), "arn:aws:iam::1:user/dev", "sts:AssumeRole", "arn:aws:iam::1:role/admin")
	if d.Known {
		t.Fatal("a decision reached without the condition context AWS asked for was reported as decided — " +
			"that closes a real path on our own missing input")
	}
	if !strings.Contains(d.Why, "MultiFactorAuthPresent") {
		t.Errorf("the missing keys must be named so a reader can supply them; got %q", d.Why)
	}
}

// An API failure is UNKNOWN, never a deny. A throttle, an expired session or a role lacking
// iam:SimulatePrincipalPolicy would otherwise silently close every path it touched — degrading proof
// quality exactly when coverage looks thinnest (ADR 0024 C10).
func TestAWSSimulator_ACallFailureIsUnknown(t *testing.T) {
	d, err := simWith(&fakeIAM{err: errors.New("Throttling: rate exceeded")}).
		Simulate(context.Background(), "arn:aws:iam::1:role/app", "s3:GetObject", "arn:aws:s3:::crown/*")
	if err == nil {
		t.Fatal("the caller must still see the transport error")
	}
	if d.Known {
		t.Fatal("a throttled call was reported as a decided verdict")
	}
}

// The result must be the answer to the question we asked. Indexing [0] blindly would let an
// unexpected multi-result response answer about a different action.
func TestAWSSimulator_OnlyTheRequestedActionAnswers(t *testing.T) {
	out := &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{
		{EvalActionName: aws.String("s3:PutObject"), EvalDecision: iamtypes.PolicyEvaluationDecisionTypeAllowed},
	}}
	d, _ := simWith(&fakeIAM{out: out}).Simulate(context.Background(), "arn:aws:iam::1:role/app", "s3:GetObject", "arn:aws:s3:::crown/*")
	if d.Known {
		t.Fatal("an evaluation for s3:PutObject was accepted as the answer for s3:GetObject")
	}
}

// AWS would answer SOMETHING for a tuple with no principal — about a different question than the one
// asked, arriving with the authority of a provider verdict. Refuse before sending.
func TestAWSSimulator_AnUnderSpecifiedTupleIsRefusedNotSent(t *testing.T) {
	f := &fakeIAM{out: evalResult("s3:GetObject", iamtypes.PolicyEvaluationDecisionTypeAllowed)}
	d, _ := simWith(f).Simulate(context.Background(), "", "s3:GetObject", "arn:aws:s3:::crown/*")
	if d.Known {
		t.Fatal("an under-specified tuple produced a decided verdict")
	}
	if f.in != nil {
		t.Fatal("the call was sent anyway — AWS evaluating a tuple we did not mean is worse than not asking")
	}
}

// The tuple must reach AWS as the tuple, or the verdict is about something else.
func TestAWSSimulator_SendsTheTupleItWasGiven(t *testing.T) {
	f := &fakeIAM{out: evalResult("s3:GetObject", iamtypes.PolicyEvaluationDecisionTypeAllowed)}
	_, _ = simWith(f).Simulate(context.Background(), "arn:aws:iam::1:role/app", "s3:GetObject", "arn:aws:s3:::crown/*")
	if f.in == nil || aws.ToString(f.in.PolicySourceArn) != "arn:aws:iam::1:role/app" {
		t.Fatalf("principal did not reach the API: %+v", f.in)
	}
	if len(f.in.ActionNames) != 1 || f.in.ActionNames[0] != "s3:GetObject" {
		t.Fatalf("action did not reach the API: %+v", f.in.ActionNames)
	}
	if len(f.in.ResourceArns) != 1 || f.in.ResourceArns[0] != "arn:aws:s3:::crown/*" {
		t.Fatalf("resource did not reach the API: %+v", f.in.ResourceArns)
	}
}

// Describe rides with every probe report, so it must state the METHOD's limits and not just the
// provider's name. A reader who sees "provider-confirmed" needs the caveat AWS publishes itself.
func TestAWSSimulator_CoverageStatesTheMethodsLimits(t *testing.T) {
	got := NewAWSSimulator("us-east-1", "arn:aws:iam::1:role/read", "").Describe()
	for _, want := range []string{"SimulatePrincipalPolicy", "resource-based", "role chaining"} {
		if !strings.Contains(got, want) {
			t.Errorf("coverage line omits %q: %s", want, got)
		}
	}
}
