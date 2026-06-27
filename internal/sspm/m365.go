package sspm

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// M365Tenant is a grounded snapshot of a Microsoft 365 tenant's COLLABORATION / DATA-SHARING posture — the
// SharePoint / OneDrive / Teams / Exchange settings that expose corporate data. This is DISTINCT from the M365
// IDENTITY posture (MFA, OAuth grants, stale accounts) the `operate` engine already covers: it closes the SSPM
// gap where we did M365's identity half but not its SharePoint/Teams data-sharing half (the gap vs the SSPM
// leaders, where M365 + Google Workspace are the two most-common SaaS estates). Sourced from the Microsoft Graph
// admin/security APIs (the credential-gated half — reuses the onboarded M365 token) or a posted snapshot.
// Snapshot-driven, LLM-free, grounded: a hardened tenant yields zero findings. Reuses the package finding/comp.
type M365Tenant struct {
	Name string `json:"name"`
	// External-sharing level for SharePoint / OneDrive: "anonymous" (Anyone links — unauthenticated) |
	// "external" (any guest) | "domains" (allowlisted) | "internal" (off). Anonymous is the worst.
	SharePointSharing       string `json:"sharepoint_sharing"`
	OneDriveSharing         string `json:"onedrive_sharing"`
	ExternalDomainAllowlist bool   `json:"external_domain_allowlist"` // external sharing limited to allowlisted domains
	TeamsGuestAccess        bool   `json:"teams_guest_access"`        // guests can be added to Teams
	TeamsGuestUnrestricted  bool   `json:"teams_guest_unrestricted"`  // no guest-access policy (guests get broad access)
	TeamsOpenFederation     bool   `json:"teams_open_federation"`     // external federation open to ALL domains
	LegacyAuthEnabled       bool   `json:"legacy_auth_enabled"`       // basic/legacy auth allowed (password-spray + MFA-bypass)
	MailboxAuditingEnabled  bool   `json:"mailbox_auditing_enabled"`  // mailbox audit logging on
	AnonymousCalendarShare  bool   `json:"anonymous_calendar_share"`  // calendar details shared anonymously
}

// AssessM365 runs every grounded collaboration/data-sharing posture check over an M365 snapshot. A securely
// configured tenant returns nil.
func AssessM365(t M365Tenant, opts Options) []types.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-m365-%03d", n) }
	target := "m365:" + t.Name

	var f []types.Finding
	if strings.EqualFold(t.SharePointSharing, "anonymous") {
		f = append(f, finding(id(), "sspm::m365::sharepoint-anonymous-sharing", types.SeverityHigh,
			"SharePoint allows anonymous ('Anyone') sharing links", target+"/sharepoint",
			"SharePoint external sharing is set to 'Anyone' — anonymous, unauthenticated links to corporate documents. Restrict to 'Only people in your organization' or specific/allowlisted domains.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, PCI: []string{"7.2.1"}, HIPAA: []string{"164.312(a)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if strings.EqualFold(t.OneDriveSharing, "anonymous") {
		f = append(f, finding(id(), "sspm::m365::onedrive-anonymous-sharing", types.SeverityHigh,
			"OneDrive allows anonymous ('Anyone') sharing links", target+"/onedrive",
			"OneDrive external sharing is set to 'Anyone' — anonymous links to users' files. Restrict OneDrive sharing to no more than the SharePoint level.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, HIPAA: []string{"164.312(a)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if (strings.EqualFold(t.SharePointSharing, "external") || strings.EqualFold(t.OneDriveSharing, "external")) && !t.ExternalDomainAllowlist {
		f = append(f, finding(id(), "sspm::m365::external-sharing-no-allowlist", types.SeverityMedium,
			"External file sharing is not restricted to allowlisted domains", target,
			"SharePoint/OneDrive allow sharing with any external user. Restrict external sharing to an allowlist of trusted partner domains to limit data leaving the tenant.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, GDPR: []string{"Art. 32"}})))
	}
	if t.TeamsGuestAccess && t.TeamsGuestUnrestricted {
		f = append(f, finding(id(), "sspm::m365::teams-guest-unrestricted", types.SeverityMedium,
			"Teams guest access has no guest-access policy", target+"/teams",
			"Guests can join Teams with no guest-access policy restricting what they can see/do. Apply a guest-access policy (restrict channels, file access, and screen sharing).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}})))
	}
	if t.TeamsOpenFederation {
		f = append(f, finding(id(), "sspm::m365::teams-open-federation", types.SeverityMedium,
			"Teams external federation is open to all domains", target+"/teams",
			"Teams external federation allows messaging with ANY external domain — a phishing / data-exfil channel. Restrict federation to an allowlist of trusted domains.",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"9.2"}, NISTCSF: []string{"PR.AC-5"}})))
	}
	if t.LegacyAuthEnabled {
		f = append(f, finding(id(), "sspm::m365::legacy-auth-enabled", types.SeverityHigh,
			"Legacy (basic) authentication is enabled", target,
			"Legacy auth protocols (POP/IMAP/SMTP basic auth, EWS) bypass MFA and are the primary password-spray vector in M365. Block legacy authentication via a Conditional Access policy.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AC-7"}, NIST80053: []string{"IA-2"}})))
	}
	if !t.MailboxAuditingEnabled {
		f = append(f, finding(id(), "sspm::m365::mailbox-auditing-disabled", types.SeverityMedium,
			"Mailbox audit logging is disabled", target+"/exchange",
			"Mailbox auditing is off, so mailbox access/forwarding/deletion isn't logged — blinding incident response + breach investigation. Enable mailbox auditing tenant-wide.",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, PCI: []string{"10.2.1"}, HIPAA: []string{"164.312(b)"}, CISv8: []string{"8.2"}, NISTCSF: []string{"DE.CM-1"}, NIST80053: []string{"AU-2"}})))
	}
	if t.AnonymousCalendarShare {
		f = append(f, finding(id(), "sspm::m365::anonymous-calendar-sharing", types.SeverityLow,
			"Calendar details are shared anonymously", target+"/exchange",
			"Calendars publish details to anonymous external users — leaking meeting subjects, attendees, and availability (useful for social-engineering). Restrict calendar sharing to free/busy or internal-only.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, NISTCSF: []string{"PR.DS-1"}})))
	}
	return f
}
