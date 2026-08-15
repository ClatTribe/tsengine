package connector

import "testing"

// ── EVERY CONNECTOR MUST BE ABLE TO SAY IT IS NOT SET UP ─────────────────────────────────────────

// The three cloud connectors did not implement Configured(), so connector.IsConfigured defaulted them
// to true and /v1/connect/aws returned 200 with a CloudFormation link whose templateURL and
// TrustedAccountId were EMPTY. The customer clicked "Connect AWS", landed on the console, and the
// stack could not be created — a dead end that looks like a working button.
func TestCloudConnectors_ReportUnconfigured(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  Connector // missing its required operator config
		good Connector
	}{
		{"aws", NewAWS("", "", "us-east-1"), NewAWS("https://s3/tpl.yaml", "1234567890", "us-east-1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if IsConfigured(tc.bad) {
				t.Error("a connector with no operator config reported itself configured — the customer " +
					"gets an authorize URL that cannot work")
			}
			if !IsConfigured(tc.good) {
				t.Error("a fully-configured connector reported itself unconfigured")
			}
		})
	}
}

// AWS needs BOTH the template and the trusted account; either alone cannot complete onboarding.
func TestAWSConfigured_NeedsBothFields(t *testing.T) {
	if IsConfigured(NewAWS("https://s3/tpl.yaml", "", "us-east-1")) {
		t.Error("a template with no trusted account reported configured")
	}
	if IsConfigured(NewAWS("", "1234567890", "us-east-1")) {
		t.Error("a trusted account with no template reported configured")
	}
}
