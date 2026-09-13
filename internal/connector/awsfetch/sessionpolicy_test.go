package awsfetch

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/internal/cloudsafety"
)

// Every live inventory read assumes the customer's role WITH the read-only STS session policy AND
// the external-id guard. This is the claim the docs make about the read path and never enforced:
// the mutator applies both, and the policy it applies is the read-only cap that denies mutation and
// data-contents reads (checked through the independent IAM evaluator, so a broken SessionPolicy
// would fail here, not silently scope down to nothing).
func TestScopeDownOptions_AppliesTheReadOnlySessionPolicyAndExternalID(t *testing.T) {
	var o stscreds.AssumeRoleOptions
	scopeDownOptions("tenant-42")(&o)

	if aws.ToString(o.ExternalID) != "tenant-42" {
		t.Errorf("the external-id confused-deputy guard must be set, got %q", aws.ToString(o.ExternalID))
	}
	if o.Policy == nil || *o.Policy == "" {
		t.Fatal("no session policy applied — the live read runs with the role's full permissions, which every doc says it does not")
	}
	doc, err := cloudiam.Parse([]byte(*o.Policy))
	if err != nil {
		t.Fatalf("the applied session policy is not valid JSON: %v", err)
	}
	for _, a := range []string{"iam:CreateUser", "s3:PutBucketPolicy", "s3:GetObject", "secretsmanager:GetSecretValue"} {
		if dec, _ := cloudiam.Eval(a, "*", doc); dec != cloudiam.ExplicitDeny {
			t.Errorf("the applied policy must explicitly Deny %s (a read that could mutate or exfiltrate is not read-only)", a)
		}
	}
	for _, a := range []string{"ec2:DescribeInstances", "s3:ListBuckets", "iam:GetRole"} {
		if dec, _ := cloudiam.Eval(a, "*", doc); dec == cloudiam.ExplicitDeny {
			t.Errorf("the applied policy must NOT Deny the metadata read %s, or the inventory fetch itself breaks", a)
		}
	}
	// It is the same document cloudsafety publishes — one source of truth, not a second copy.
	if *o.Policy != cloudsafety.SessionPolicy() {
		t.Error("the applied policy must be cloudsafety.SessionPolicy() verbatim, not a divergent copy")
	}

	// An empty external id sets none (an operator-credentialed path with no confused-deputy risk),
	// but the session policy is applied REGARDLESS — the cap does not depend on the guard.
	var o2 stscreds.AssumeRoleOptions
	scopeDownOptions("")(&o2)
	if o2.ExternalID != nil {
		t.Errorf("empty external id must set none, got %q", aws.ToString(o2.ExternalID))
	}
	if o2.Policy == nil || *o2.Policy == "" {
		t.Error("the session policy must be applied even without an external id")
	}
}
