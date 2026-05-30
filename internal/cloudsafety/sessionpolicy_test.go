package cloudsafety_test

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/internal/cloudsafety"
)

// The generated session policy is cross-checked with the independent IAM
// evaluator: dangerous actions must evaluate to an explicit Deny, read-only
// ones must not be denied by it.
func TestSessionPolicy_DeniesDangerousAllowsReadOnly(t *testing.T) {
	doc, err := cloudiam.Parse([]byte(cloudsafety.SessionPolicy()))
	if err != nil {
		t.Fatalf("generated session policy is not valid JSON: %v", err)
	}

	mustDeny := []string{
		"iam:CreateUser", "iam:PassRole", "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
		"sts:AssumeRole", "s3:PutBucketPolicy", "s3:DeleteObject", "ec2:RunInstances",
		"lambda:CreateFunction", "kms:Disable", "secretsmanager:PutSecretValue",
		// data contents
		"s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt", "dynamodb:GetItem",
	}
	for _, a := range mustDeny {
		if dec, _ := cloudiam.Eval(a, "*", doc); dec != cloudiam.ExplicitDeny {
			t.Errorf("session policy must explicitly Deny %s (got %v)", a, dec)
		}
	}

	// read-only metadata reads must NOT be denied by the session policy.
	mustNotDeny := []string{
		"ec2:DescribeInstances", "iam:GetRole", "s3:ListBuckets",
		"iam:SimulatePrincipalPolicy", "s3:GetBucketPolicy",
	}
	for _, a := range mustNotDeny {
		if dec, _ := cloudiam.Eval(a, "*", doc); dec == cloudiam.ExplicitDeny {
			t.Errorf("session policy must NOT Deny read-only %s", a)
		}
	}
}
