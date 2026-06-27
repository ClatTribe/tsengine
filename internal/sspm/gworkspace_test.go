package sspm

import (
	"testing"
	"time"
)

func TestAssessGoogleWorkspace_FlagsMisconfig(t *testing.T) {
	bad := GWorkspaceTenant{
		Name: "northwind", DriveSharing: "public", DriveLinkSharingDefault: true,
		LessSecureAppsEnabled: true, ThirdPartyAPIAccess: true,
		GmailExternalAutoForward: true, ExternalCalendarSharing: true,
	}
	got := map[string]bool{}
	for _, x := range AssessGoogleWorkspace(bad, Options{Now: time.Now()}) {
		got[x.RuleID] = true
		if x.Compliance == nil {
			t.Errorf("%s missing compliance annotation", x.RuleID)
		}
	}
	for _, want := range []string{
		"sspm::google_workspace::drive-public-sharing", "sspm::google_workspace::drive-link-sharing-default",
		"sspm::google_workspace::less-secure-apps-enabled", "sspm::google_workspace::third-party-app-access-unrestricted",
		"sspm::google_workspace::gmail-external-autoforward", "sspm::google_workspace::external-calendar-sharing",
	} {
		if !got[want] {
			t.Errorf("expected finding %q", want)
		}
	}
}

func TestAssessGoogleWorkspace_HardenedClean(t *testing.T) {
	good := GWorkspaceTenant{Name: "acme", DriveSharing: "restricted", DriveExternalAllowlist: true}
	if f := AssessGoogleWorkspace(good, Options{Now: time.Now()}); len(f) != 0 {
		t.Errorf("a hardened Google Workspace must yield zero findings, got %d: %+v", len(f), f)
	}
}
