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
		// auditing explicitly reported as OFF by the snapshot → flagged. (Omitting the
		// field now means "not supplied" and is asserted separately below.)
		MailboxAuditingEnabled: BoolPtr(false),
		TeamsGuestAccess:       true, TeamsGuestUnrestricted: true,
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
		ExternalDomainAllowlist: true, MailboxAuditingEnabled: BoolPtr(true),
		// legacy auth off, no open federation, no anon calendar, no unrestricted guests
	}
	if f := AssessM365(good, Options{Now: time.Now()}); len(f) != 0 {
		t.Errorf("a hardened M365 tenant must yield zero findings, got %d: %+v", len(f), f)
	}
}

// The tri-state guard: a snapshot that never carried Exchange posture must NOT be
// reported as having mailbox auditing disabled. Every live Graph sync is in this
// position, because mailbox auditing is only readable via Exchange PowerShell — so a
// plain bool here made the live path emit a guaranteed false positive.
func TestAssessM365_UnsuppliedMailboxAuditingIsNotAFinding(t *testing.T) {
	for _, f := range AssessM365(M365Tenant{Name: "unknown-exchange"}, Options{Now: time.Now()}) {
		if f.RuleID == "sspm::m365::mailbox-auditing-disabled" {
			t.Error("an unsupplied mailbox-auditing setting must not be reported as disabled")
		}
	}
	// ...while an explicit false still is.
	var flagged bool
	for _, f := range AssessM365(M365Tenant{Name: "off", MailboxAuditingEnabled: BoolPtr(false)}, Options{Now: time.Now()}) {
		if f.RuleID == "sspm::m365::mailbox-auditing-disabled" {
			flagged = true
		}
	}
	if !flagged {
		t.Error("an explicitly-disabled mailbox audit must still be flagged")
	}
}
