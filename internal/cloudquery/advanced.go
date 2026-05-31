package cloudquery

import (
	"encoding/json"
	"fmt"
)

// GenerateAdvanced emulates a CloudQuery account that exercises the IAM
// dimensions the earlier ingest dropped — resource-based (bucket) policies and
// org SCPs — so the dual-view is visibly driven by effective-permission
// reasoning, not just topology:
//
//   - a sensitive bucket (cardholder) reachable ONLY via its bucket policy
//     (reader-role has no identity grant). A real path the engine finds only by
//     evaluating the resource policy.
//   - a privesc that is real by identity policy but DENIED by an account SCP
//     (esc-role). prowler flags it; the engineer downgrades it because the SCP
//     blocks the escalation — the dual-view payoff.
//
// plus a normal network→data path (web-role → pii) and a public non-sensitive
// bucket, as controls. The answer key is validated with cloudiam (the resource
// policy and SCP are each shown to be load-bearing).
func GenerateAdvanced() (*Dataset, error) {
	ec2Trust := allowDoc("sts:AssumeRole", "ec2.amazonaws.com")
	const (
		piiB  = "arn:aws:s3:::acme-customer-pii"
		cardB = "arn:aws:s3:::acme-cardholder-data"
		logsB = "arn:aws:s3:::acme-public-logs"
		webR  = roleP + "web-role"
		readR = roleP + "reader-role"
		escR  = roleP + "esc-role"
	)
	// reader-role's ONLY grant to cardholder is this bucket (resource) policy.
	cardPolicy := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + readR + `"},"Action":"s3:GetObject","Resource":"` + cardB + `/*"}]}`)

	t := &Tables{
		SecurityGroups: []SecurityGroup{{ID: "sg-open", Name: "open-to-world", OpenIngressFromInternet: true}},
		S3Buckets: []S3Bucket{
			{ARN: piiB, Name: "acme-customer-pii", Region: "us-east-1", BlockPublicACLs: true, BlockPublicPolicy: true, Tags: map[string]string{"classification": "pii"}},
			{ARN: cardB, Name: "acme-cardholder-data", Region: "us-east-1", BlockPublicACLs: true, BlockPublicPolicy: true, Policy: cardPolicy, Tags: map[string]string{"classification": "pii"}},
			{ARN: logsB, Name: "acme-public-logs", Region: "us-east-1", PolicyAllowsPublic: true, MFADelete: true},
		},
		IAMRoles: []IAMRole{
			{ARN: webR, Name: "web-role", AssumeRolePolicyDocument: ec2Trust, InlinePolicies: raws(allowDoc("s3:GetObject", piiB))},
			{ARN: readR, Name: "reader-role", AssumeRolePolicyDocument: ec2Trust}, // NO identity grant
			{ARN: escR, Name: "esc-role", AssumeRolePolicyDocument: ec2Trust, InlinePolicies: raws(allowDoc("iam:CreatePolicyVersion", "*"))},
		},
		EC2Instances: []EC2Instance{
			{ARN: ec2P + "i-web", Name: "web", PublicIPAddress: "203.0.113.10", IAMInstanceProfileRoleARN: webR, SecurityGroupIDs: []string{"sg-open"}},
			{ARN: ec2P + "i-reader", Name: "reader", PublicIPAddress: "203.0.113.11", IAMInstanceProfileRoleARN: readR, SecurityGroupIDs: []string{"sg-open"}},
			{ARN: ec2P + "i-esc", Name: "esc", PublicIPAddress: "203.0.113.12", IAMInstanceProfileRoleARN: escR, SecurityGroupIDs: []string{"sg-open"}},
		},
		// default FullAWSAccess + a restrictive SCP denying iam:* (blocks esc-role).
		SCPs: raws(
			json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
			json.RawMessage(`{"Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`),
		),
	}

	ds := &Dataset{Tables: t, AnswerKey: AnswerKey{
		RealTargets: []string{piiB, cardB},
		InertFindings: []string{
			FindingID("iam_policy_allows_privilege_escalation", escR), // SCP-blocked
			FindingID("s3_bucket_public_access", logsB),               // non-sensitive
		},
	}}
	if err := ds.validateAdvanced(readR, cardB, escR); err != nil {
		return nil, err
	}
	return ds, nil
}

// validateAdvanced proves (with cloudiam, not the engine) that the resource
// policy and the SCP are each load-bearing — so a pass is meaningful.
func (ds *Dataset) validateAdvanced(readerARN, cardARN, escARN string) error {
	scps := parseDocs(ds.Tables.SCPs)
	var cardPolicy json.RawMessage
	for _, b := range ds.Tables.S3Buckets {
		if b.ARN == cardARN {
			cardPolicy = b.Policy
		}
	}
	if ok, _ := canReadBucket(readerARN, cardARN, nil, nil, nil, nil); ok {
		return fmt.Errorf("advanced: reader must not read cardholder without the bucket policy")
	}
	if ok, _ := canReadBucket(readerARN, cardARN, nil, nil, scps, parseDoc(cardPolicy)); !ok {
		return fmt.Errorf("advanced: reader must read cardholder via the bucket policy")
	}
	escPol := parseDocs(raws(allowDoc("iam:CreatePolicyVersion", "*")))
	if _, ok := detectPrivesc(escARN, escPol, nil, nil); !ok {
		return fmt.Errorf("advanced: esc-role must escalate without the SCP")
	}
	if _, ok := detectPrivesc(escARN, escPol, nil, scps); ok {
		return fmt.Errorf("advanced: esc-role escalation must be blocked by the SCP")
	}
	return nil
}
