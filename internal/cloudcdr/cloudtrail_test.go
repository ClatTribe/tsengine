package cloudcdr

import (
	"strings"
	"testing"
)

const rootLogin = `{"eventVersion":"1.08","userIdentity":{"type":"Root","principalId":"123456789012","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012"},
"eventTime":"2026-09-13T11:02:03Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9",
"requestParameters":null,"responseElements":{"ConsoleLogin":"Success"}}`

const sgOpened = `{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/Deploy/ci","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::123456789012:role/Deploy"}}},
"eventName":"AuthorizeSecurityGroupIngress","awsRegion":"eu-west-1","sourceIPAddress":"10.0.0.5",
"requestParameters":{"groupId":"sg-0abc","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}}`

const attachAdmin = `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/intern","userName":"intern"},
"eventName":"AttachUserPolicy","awsRegion":"us-east-1",
"requestParameters":{"userName":"intern","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},
"resources":[{"ARN":"arn:aws:iam::123456789012:user/intern","type":"AWS::IAM::User"}]}`

const stopLogging = `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ops"},"eventName":"StopLogging","awsRegion":"us-east-1",
"requestParameters":{"name":"arn:aws:cloudtrail:us-east-1:123456789012:trail/main"}}`

// A real CloudTrail record becomes the Event the rules already classify, and the rules then fire
// on it — the whole reason the poller exists is that these four were undetectable without a
// customer-built forwarder.
func TestFromCloudTrail_NormalisesTheFieldsTheRulesKeyOn(t *testing.T) {
	root, ok := FromCloudTrail([]byte(rootLogin))
	if !ok || root.Actor != "root" || root.EventName != "ConsoleLogin" || root.SourceIP != "203.0.113.9" || root.Region != "us-east-1" || root.Provider != "aws" {
		t.Errorf("root login: %+v", root)
	}
	if root.Detail != "" {
		t.Errorf("null request parameters must yield no detail, got %q", root.Detail)
	}
	sg, ok := FromCloudTrail([]byte(sgOpened))
	if !ok || sg.Actor != "arn:aws:sts::123456789012:assumed-role/Deploy/ci" || sg.Resource != "sg-0abc" || !strings.Contains(sg.Detail, "0.0.0.0/0") {
		t.Errorf("sg opened: %+v", sg)
	}
	adm, ok := FromCloudTrail([]byte(attachAdmin))
	if !ok || adm.Resource != "arn:aws:iam::123456789012:user/intern" || !strings.Contains(adm.Detail, "AdministratorAccess") {
		t.Errorf("attach admin: the resource ARN CloudTrail attributes wins over the parameter: %+v", adm)
	}
	stop, ok := FromCloudTrail([]byte(stopLogging))
	if !ok || !strings.Contains(stop.Resource, "trail/main") {
		t.Errorf("stop logging: %+v", stop)
	}

	// End to end through the rules: all four fire.
	evs, dropped := FromCloudTrailBatch([][]byte{[]byte(rootLogin), []byte(sgOpened), []byte(attachAdmin), []byte(stopLogging), []byte(`not json`), []byte(`{"eventSource":"x"}`)})
	if dropped != 2 || len(evs) != 4 {
		t.Fatalf("unreadable and nameless records must be dropped AND counted: dropped=%d events=%d", dropped, len(evs))
	}
	seen := map[string]bool{}
	for _, th := range Detect(evs) {
		seen[th.Rule] = true
	}
	for _, want := range []string{"root_console_login", "security_group_opened", "iam_privilege_escalation", "audit_logging_disabled"} {
		if !seen[want] {
			t.Errorf("rule %s did not fire on the normalised record; seen=%v", want, seen)
		}
	}
}

// A benign management event normalises without becoming a threat — the rules stay grounded on the
// values, and the normaliser must not manufacture any.
func TestFromCloudTrail_BenignEventIsNotAThreat(t *testing.T) {
	ev, ok := FromCloudTrail([]byte(`{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/dev"},"eventName":"DescribeInstances","awsRegion":"us-east-1","requestParameters":{"maxResults":50}}`))
	if !ok || ev.Actor != "arn:aws:iam::1:user/dev" {
		t.Fatalf("benign: %+v", ev)
	}
	if th := Detect([]Event{ev}); len(th) != 0 {
		t.Errorf("a read-only call must not be a threat: %+v", th)
	}
}
