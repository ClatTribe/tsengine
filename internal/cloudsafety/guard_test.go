package cloudsafety

import (
	"errors"
	"testing"
)

func TestReadOnly(t *testing.T) {
	allow := []string{
		"s3:ListBuckets", "s3:GetBucketPolicy", "ec2:DescribeInstances",
		"iam:SimulatePrincipalPolicy", "iam:GetRole", "s3:HeadObject",
		"accessanalyzer:GenerateFindings",
	}
	for _, a := range allow {
		if !ReadOnly(a) {
			t.Errorf("%s should be read-only", a)
		}
	}
	deny := []string{
		// mutating
		"s3:PutBucketPolicy", "iam:CreatePolicyVersion", "ec2:RunInstances",
		"sts:AssumeRole", "iam:PassRole", "lambda:CreateFunction",
		// read-only-looking but DATA contents (metadata-only rule)
		"s3:GetObject", "secretsmanager:GetSecretValue", "ssm:GetParameter",
		"dynamodb:GetItem", "kms:Decrypt",
	}
	for _, a := range deny {
		if ReadOnly(a) {
			t.Errorf("%s must NOT be allowed (mutating or data-contents)", a)
		}
	}
}

func TestGuard_BlocksMutating(t *testing.T) {
	g := NewGuard(10)
	err := g.Allow("s3:PutBucketPolicy", "h1")
	if !errors.Is(err, ErrMutating) {
		t.Fatalf("want ErrMutating, got %v", err)
	}
	if g.Used() != 0 {
		t.Error("a denied action must not consume budget")
	}
	if l := g.Log(); len(l) != 1 || l[0].Allowed {
		t.Errorf("denied attempt should be logged as not-allowed: %+v", l)
	}
}

func TestGuard_AllowsReadOnlyWithinBudget(t *testing.T) {
	g := NewGuard(2)
	if err := g.Allow("ec2:DescribeInstances", "h1"); err != nil {
		t.Fatalf("read-only within budget should pass: %v", err)
	}
	if err := g.Allow("iam:SimulatePrincipalPolicy", "h1"); err != nil {
		t.Fatalf("second read-only within budget should pass: %v", err)
	}
	if g.Used() != 2 {
		t.Errorf("used = %d, want 2", g.Used())
	}
	// third exceeds budget
	if err := g.Allow("s3:ListBuckets", "h1"); !errors.Is(err, ErrBudget) {
		t.Fatalf("want ErrBudget, got %v", err)
	}
}

func TestGuard_DataContentsAlwaysDenied(t *testing.T) {
	g := NewGuard(100)
	if err := g.Allow("s3:GetObject", "h1"); !errors.Is(err, ErrMutating) {
		// data-contents reads are denied via the read-only check (not ReadOnly)
		t.Fatalf("s3:GetObject (data contents) must be denied, got %v", err)
	}
	if g.Used() != 0 {
		t.Error("denied data read must not consume budget")
	}
}
