package cloudquery

import (
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// TestCloudQuery_ResourcePolicyAndSCP proves the engine now reasons over the two
// dimensions the earlier ingest dropped — and that they are load-bearing:
//
//   - a sensitive bucket reachable ONLY via its RESOURCE (bucket) policy — the
//     reader role has no identity grant. The old identity-only ingest would MISS
//     this real path; the engine must now find it.
//   - a privesc that is real by identity policy but DENIED by an account SCP. The
//     old SCP-blind ingest would FALSE-POSITIVE a path to admin; the engine must
//     now NOT report one.
func TestCloudQuery_ResourcePolicyAndSCP(t *testing.T) {
	const acct = "arn:aws:iam::123456789012:"
	bucket := "arn:aws:s3:::cq-cardholder"
	reader := acct + "role/reader-role"
	esc := acct + "role/esc-role"
	ec2A := "arn:aws:ec2:us-east-1:123456789012:instance/i-a"
	ec2B := "arn:aws:ec2:us-east-1:123456789012:instance/i-b"

	ec2Trust := allowDoc("sts:AssumeRole", "ec2.amazonaws.com")
	bucketPolicy := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + reader + `"},"Action":"s3:GetObject","Resource":"` + bucket + `/*"}]}`)

	t.Setenv("TZ", "UTC") // determinism hygiene (no effect on logic)

	tables := &Tables{
		SecurityGroups: []SecurityGroup{{ID: "sg-open", Name: "open", OpenIngressFromInternet: true}},
		S3Buckets: []S3Bucket{{
			ARN: bucket, Name: "cq-cardholder", Region: "us-east-1",
			BlockPublicACLs: true, BlockPublicPolicy: true, MFADelete: true,
			Policy: bucketPolicy, // resource policy is the ONLY grant to reader-role
			Tags:   map[string]string{"classification": "pii"},
		}},
		IAMRoles: []IAMRole{
			// reader-role: NO identity policy → access can only come from the bucket policy.
			{ARN: reader, Name: "reader-role", AssumeRolePolicyDocument: ec2Trust},
			// esc-role: identity grants a privesc primitive, but an SCP denies iam:*.
			{ARN: esc, Name: "esc-role", AssumeRolePolicyDocument: ec2Trust,
				InlinePolicies: raws(allowDoc("iam:CreatePolicyVersion", "*"))},
		},
		EC2Instances: []EC2Instance{
			{ARN: ec2A, Name: "a", PublicIPAddress: "203.0.113.20", IAMInstanceProfileRoleARN: reader, SecurityGroupIDs: []string{"sg-open"}},
			{ARN: ec2B, Name: "b", PublicIPAddress: "203.0.113.21", IAMInstanceProfileRoleARN: esc, SecurityGroupIDs: []string{"sg-open"}},
		},
		// Real accounts keep the default FullAWSAccess allow; the restrictive SCP
		// ADDS a Deny on iam:*.
		SCPs: raws(
			json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
			json.RawMessage(`{"Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`),
		),
	}

	// --- independent (cloudiam) ground truth: the two dimensions are load-bearing ---
	scps := parseDocs(tables.SCPs)
	bpDoc := parseDoc(bucketPolicy)
	if ok, _ := canReadBucket(reader, bucket, nil, nil, nil, nil); ok {
		t.Fatal("setup: reader must NOT read the bucket without the resource policy")
	}
	if ok, _ := canReadBucket(reader, bucket, nil, nil, scps, bpDoc); !ok {
		t.Fatal("setup: reader MUST read the bucket via the resource policy")
	}
	if _, ok := detectPrivesc(esc, parseDocs(raws(allowDoc("iam:CreatePolicyVersion", "*"))), nil, nil); !ok {
		t.Fatal("setup: esc-role MUST escalate without the SCP")
	}
	if _, ok := detectPrivesc(esc, parseDocs(raws(allowDoc("iam:CreatePolicyVersion", "*"))), nil, scps); ok {
		t.Fatal("setup: esc-role escalation MUST be blocked by the SCP")
	}

	// --- the engine, ingesting via the full Authorize ---
	a := cloudengine.Assess(cloudgraph.Ingest(ToInventory(tables)), EvalProwler(tables),
		cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: 40})

	reachedBucket, reachedAdmin := false, false
	for _, p := range a.Paths {
		switch pathEndID(p) {
		case bucket:
			reachedBucket = true
		case cloudgraph.AdminID:
			reachedAdmin = true
		}
	}
	if !reachedBucket {
		t.Error("engine must find the path to the sensitive bucket granted via its RESOURCE policy")
	}
	if reachedAdmin {
		t.Error("engine must NOT report a privesc-to-admin path the SCP blocks")
	}
}
