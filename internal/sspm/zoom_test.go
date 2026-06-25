package sspm

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// a fully hardened account — every check must pass → zero findings (the testability invariant).
func hardenedZoom() ZoomAccount {
	return ZoomAccount{
		Name:                    "acme",
		TwoFactorRequired:       true,
		SSOEnforced:             true,
		MeetingPasscodeRequired: true,
		WaitingRoomEnabled:      true,
		CloudRecordingEncrypted: true,
		RecordingAutoDelete:     true,
		ApprovedAppsOnly:        true,
		Members: []ZoomMember{
			{Email: "ceo@acme.com", Role: "owner", TwoFactor: true},
			{Email: "dev@acme.com", Role: "member", TwoFactor: true},
		},
		Apps: []ZoomApp{{Name: "Otter.ai", Verified: true, BroadScope: false}},
	}
}

func TestAssessZoom_HardenedYieldsZero(t *testing.T) {
	if f := AssessZoom(hardenedZoom(), Options{}); len(f) != 0 {
		t.Fatalf("a hardened Zoom account must yield zero findings, got %d: %+v", len(f), f)
	}
}

func TestAssessZoom_FlagsMisconfig(t *testing.T) {
	acc := ZoomAccount{
		Name:                    "acme",
		TwoFactorRequired:       false,
		SSOEnforced:             false,
		MeetingPasscodeRequired: false,
		WaitingRoomEnabled:      false,
		CloudRecordingEncrypted: false,
		RecordingAutoDelete:     false,
		ApprovedAppsOnly:        false,
		Members: []ZoomMember{
			{Email: "ceo@acme.com", Role: "owner", TwoFactor: false},
			{Email: "dev@acme.com", Role: "member", TwoFactor: false},
		},
		Apps: []ZoomApp{
			{Name: "ShadyBot", Verified: false, BroadScope: true},
		},
	}
	f := AssessZoom(acc, Options{})
	rules := map[string]types.Severity{}
	for _, x := range f {
		rules[x.RuleID] = x.Severity
		if x.Tool != "sspm" || x.VerificationStatus != types.VerificationVerified {
			t.Errorf("finding not grounded-verified: %+v", x)
		}
		if !strings.HasPrefix(x.Endpoint, "zoom:acme") {
			t.Errorf("endpoint not grounded to the account: %q", x.Endpoint)
		}
	}
	for _, want := range []string{
		"sspm::zoom::2fa-not-enforced",
		"sspm::zoom::sso-not-enforced",
		"sspm::zoom::meeting-passcode-not-required",
		"sspm::zoom::waiting-room-disabled",
		"sspm::zoom::cloud-recording-not-protected",
		"sspm::zoom::no-recording-retention",
		"sspm::zoom::app-approval-disabled",
		"sspm::zoom::member-without-2fa",
		"sspm::zoom::app-broad-scope",
	} {
		if _, ok := rules[want]; !ok {
			t.Errorf("expected finding %q not emitted", want)
		}
	}
	// the owner-without-2FA must be high severity
	if rules["sspm::zoom::2fa-not-enforced"] != types.SeverityHigh {
		t.Errorf("2fa-not-enforced should be high, got %q", rules["sspm::zoom::2fa-not-enforced"])
	}
}

func TestAssessZoom_AdminSprawl(t *testing.T) {
	acc := hardenedZoom() // hardened except admin count
	acc.Members = []ZoomMember{
		{Email: "a@x", Role: "owner", TwoFactor: true},
		{Email: "b@x", Role: "admin", TwoFactor: true},
		{Email: "c@x", Role: "admin", TwoFactor: true},
		{Email: "d@x", Role: "admin", TwoFactor: true},
	}
	f := AssessZoom(acc, Options{MaxOwners: 3})
	if len(f) != 1 || f[0].RuleID != "sspm::zoom::admin-sprawl" {
		t.Fatalf("want exactly the admin-sprawl finding, got %+v", f)
	}
}
