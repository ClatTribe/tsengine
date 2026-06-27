package sspm

import (
	"testing"
	"time"
)

func TestAssessM365_FlagsMisconfig(t *testing.T) {
	bad := M365Tenant{
		Name:              "northwind",
		SharePointSharing: "anonymous",
		OneDriveSharing:   "anonymous",
		LegacyAuthEnabled: true,
		// MailboxAuditingEnabled: false → flagged
		TeamsGuestAccess: true, TeamsGuestUnrestricted: true,
		TeamsOpenFederation:    true,
		AnonymousCalendarShare: true,
	}
	f := AssessM365(bad, Options{Now: time.Now()})
	got := map[string]bool{}
	for _, x := range f {
		got[x.RuleID] = true
	}
	for _, want := range []string{
		"sspm::m365::sharepoint-anonymous-sharing", "sspm::m365::onedrive-anonymous-sharing",
		"sspm::m365::legacy-auth-enabled", "sspm::m365::mailbox-auditing-disabled",
		"sspm::m365::teams-guest-unrestricted", "sspm::m365::teams-open-federation",
		"sspm::m365::anonymous-calendar-sharing",
	} {
		if !got[want] {
			t.Errorf("expected finding %q", want)
		}
	}
	// every finding carries a compliance annotation (grounded, flows to grc)
	for _, x := range f {
		if x.Compliance == nil {
			t.Errorf("%s missing compliance annotation", x.RuleID)
		}
	}
}

func TestAssessM365_HardenedTenantClean(t *testing.T) {
	good := M365Tenant{
		Name: "acme", SharePointSharing: "domains", OneDriveSharing: "internal",
		ExternalDomainAllowlist: true, MailboxAuditingEnabled: true,
		// legacy auth off, no open federation, no anon calendar, no unrestricted guests
	}
	if f := AssessM365(good, Options{Now: time.Now()}); len(f) != 0 {
		t.Errorf("a hardened M365 tenant must yield zero findings, got %d: %+v", len(f), f)
	}
}
