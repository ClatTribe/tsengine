package cloudcdr

import "testing"

func TestDetect(t *testing.T) {
	events := []Event{
		{Provider: "aws", EventName: "PutBucketAcl", Resource: "arn:aws:s3:::reports", Detail: "grantee=AllUsers permission=READ"},
		{Provider: "aws", EventName: "AuthorizeSecurityGroupIngress", Resource: "sg-1", Detail: "cidr=0.0.0.0/0 port=22"},
		{Provider: "aws", EventName: "ConsoleLogin", Actor: "root", SourceIP: "5.6.7.8"},
		{Provider: "aws", EventName: "AttachUserPolicy", Resource: "user/intern", Detail: "policyArn=arn:aws:iam::aws:policy/AdministratorAccess"},
		{Provider: "aws", EventName: "CreateAccessKey", Resource: "user/svc"},
		{Provider: "aws", EventName: "StopLogging", Resource: "trail/main"},
		// benign / grounded negatives:
		{Provider: "aws", EventName: "DescribeInstances"},
		{Provider: "aws", EventName: "PutBucketAcl", Resource: "arn:aws:s3:::private", Detail: "grantee=owner permission=FULL_CONTROL"}, // not public → no flag
	}

	threats := Detect(events)
	seen := map[string]bool{}
	for _, th := range threats {
		seen[th.Rule+"|"+string(th.Severity)] = true
	}
	want := []string{
		"public_resource_exposure|high",
		"security_group_opened|high",
		"root_console_login|high",
		"audit_logging_disabled|high",
		"iam_privilege_escalation|high",   // AttachUserPolicy → admin
		"iam_privilege_escalation|medium", // CreateAccessKey → new credentials
	}
	if len(threats) != 6 {
		t.Fatalf("want 6 threats (2 benign ignored), got %d: %+v", len(threats), threats)
	}
	for _, wstr := range want {
		if !seen[wstr] {
			t.Errorf("missing detection: %s", wstr)
		}
	}

	// the private bucket + DescribeInstances must NOT flag (action alone isn't enough — §10 grounding)
	for _, th := range threats {
		if th.Event.EventName == "DescribeInstances" {
			t.Error("benign read action must not be flagged")
		}
	}

	// Findings map to cloudcdr:: rule ids with mitre
	fs := Findings(threats)
	if len(fs) != 6 {
		t.Fatalf("want 6 findings, got %d", len(fs))
	}
	for _, f := range fs {
		if f.Tool != "cloudcdr" || f.RuleID[:9] != "cloudcdr:" {
			t.Errorf("finding rule id/tool wrong: %+v", f)
		}
	}
}
