package cloudsafety

import (
	"encoding/json"
	"sort"
)

// SessionPolicy returns the read-only STS session policy (JSON) the engineer's
// role is assumed WITH. It is the structural credential cap (ADR 0002): even if
// the assumed role is broad, the session can only do read-only work, because
// this inline policy explicitly DENIES the dangerous action patterns across the
// high-risk services AND the data-contents reads. Paired with the AWS-managed
// `ReadOnlyAccess` (the allow side), it is defense-in-depth alongside the
// application-layer Guard — two independent barriers to mutation/exfiltration.
//
// (IAM can't express "deny everything that isn't read-only" with a single
// cross-service wildcard, so the deny list is per-service verb patterns for the
// services that carry mutation/exfil risk.)
func SessionPolicy() string {
	denyData := make([]string, 0, len(denyEvenIfReadOnlyLooking))
	for a := range denyEvenIfReadOnlyLooking {
		denyData = append(denyData, a)
	}
	sort.Strings(denyData)

	pol := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":      "DenyMutations",
				"Effect":   "Deny",
				"Action":   mutatingPatterns,
				"Resource": "*",
			},
			{
				"Sid":      "DenyDataContents",
				"Effect":   "Deny",
				"Action":   denyData,
				"Resource": "*",
			},
		},
	}
	b, _ := json.MarshalIndent(pol, "", "  ")
	return string(b)
}

// mutatingPatterns denies state-changing actions across the services that carry
// mutation / privilege / exfil risk. Service-qualified so IAM accepts them.
var mutatingPatterns = []string{
	"iam:Create*", "iam:Delete*", "iam:Put*", "iam:Update*", "iam:Attach*", "iam:Detach*", "iam:Add*", "iam:Remove*", "iam:Set*", "iam:PassRole",
	"sts:AssumeRole*",
	"s3:Put*", "s3:Delete*", "s3:Create*",
	"ec2:Run*", "ec2:Create*", "ec2:Delete*", "ec2:Modify*", "ec2:Terminate*", "ec2:Authorize*",
	"lambda:Create*", "lambda:Update*", "lambda:Delete*", "lambda:Invoke*", "lambda:Add*",
	"kms:Create*", "kms:Schedule*", "kms:Disable*", "kms:Put*",
	"secretsmanager:Put*", "secretsmanager:Create*", "secretsmanager:Update*", "secretsmanager:Delete*",
	"cloudformation:Create*", "cloudformation:Update*", "cloudformation:Delete*", "cloudformation:Execute*",
}
