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
	// MailboxAuditingEnabled is a POINTER because it is the one "true = good" field here:
	// a plain bool made its zero value (false) assert a violation, so any snapshot that
	// simply did not carry Exchange posture — every live Graph sync, since mailbox
	// auditing is Exchange-PowerShell-only — falsely reported auditing as disabled.
	// nil = not supplied (no finding); &false = really off; &true = on. An explicit
	// `"mailbox_auditing_enabled": false` in a posted snapshot behaves exactly as before.
	MailboxAuditingEnabled *bool `json:"mailbox_auditing_enabled,omitempty"`
	AnonymousCalendarShare bool  `json:"anonymous_calendar_share"` // calendar details shared anonymously

	// --- Fields below close mandatory (SHALL) gaps found by the CISA SCuBA neutral
	// benchmark (internal/bench/scuba.go). Every one is OPTIONAL and FP-safe: the
	// zero value means "the snapshot did not supply this", so a legacy snapshot
	// gains no new findings. Enum strings are lowercase; "" = not supplied.

	// ExternalAutoForwardEnabled: users may auto-forward mail to external domains —
	// the classic silent-exfil path after an account takeover. MS.EXO.1.1v2.
	// (We already detected this for Google Workspace but not for M365.)
	ExternalAutoForwardEnabled bool `json:"external_autoforward_enabled,omitempty"`
	// WeakMFAMethodsEnabled: SMS, Voice Call, or Email OTP are permitted as an MFA
	// method — phishable and SIM-swappable, so MFA is present but bypassable.
	// MS.AAD.3.5v2 (and the reason MS.AAD.3.1v1 "phishing-resistant" fails).
	WeakMFAMethodsEnabled bool `json:"weak_mfa_methods_enabled,omitempty"`
	// RiskyUserBlockDisabled / RiskySignInBlockDisabled: Entra ID Protection is not
	// blocking principals/sessions it has already flagged as high risk.
	// MS.AAD.2.1v1 / MS.AAD.2.3v1.
	RiskyUserBlockDisabled   bool `json:"risky_user_block_disabled,omitempty"`
	RiskySignInBlockDisabled bool `json:"risky_signin_block_disabled,omitempty"`
	// UserAppRegistrationAllowed: any user may register an application — a
	// self-service route to an OAuth client that can then request consent.
	// MS.AAD.5.1v1.
	UserAppRegistrationAllowed bool `json:"user_app_registration_allowed,omitempty"`
	// PermanentPrivilegedAssignments: highly privileged roles are held as permanent
	// ACTIVE assignments rather than PIM-eligible/just-in-time — standing privilege
	// that an attacker inherits the moment an account is taken over. MS.AAD.7.4v1.
	PermanentPrivilegedAssignments bool `json:"permanent_privileged_assignments,omitempty"`
	// ExternalSenderWarningsDisabled: no external-sender tagging on inbound mail,
	// removing the visual cue users rely on to spot impersonation. MS.EXO.7.1v1.
	ExternalSenderWarningsDisabled bool `json:"external_sender_warnings_disabled,omitempty"`
	// AnyoneLinkExpiryDays: lifetime of anonymous "Anyone" links in days. 0 = not
	// supplied. AnyoneLinksNeverExpire is the explicit never-expires case, which
	// must be modelled separately so 0 stays unambiguous. MS.SHAREPOINT.3.1v1.
	AnyoneLinkExpiryDays   int  `json:"anyone_link_expiry_days,omitempty"`
	AnyoneLinksNeverExpire bool `json:"anyone_links_never_expire,omitempty"`
	// DefaultSharingScope: default audience for a new share link — "anyone" |
	// "organization" | "specific" ("" = not supplied). MS.SHAREPOINT.2.1v1.
	DefaultSharingScope string `json:"default_sharing_scope,omitempty"`
	// DefaultLinkPermission: default permission on a new share link — "edit" |
	// "view" ("" = not supplied). MS.SHAREPOINT.2.2v1.
	DefaultLinkPermission string `json:"default_link_permission,omitempty"`
	// TeamsAnonymousStartMeeting: anonymous (unauthenticated) users may START a
	// meeting, not merely join one. MS.TEAMS.1.2v2.
	TeamsAnonymousStartMeeting bool `json:"teams_anonymous_start_meeting,omitempty"`
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
	if t.MailboxAuditingEnabled != nil && !*t.MailboxAuditingEnabled {
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

	// --- Checks closing mandatory CISA SCuBA gaps (see the struct comment). Each
	// fires only on an explicitly-supplied signal, so a snapshot that omits the
	// field stays clean.

	if t.ExternalAutoForwardEnabled {
		f = append(f, finding(id(), "sspm::m365::external-autoforward-allowed", types.SeverityHigh,
			"Mail auto-forwarding to external domains is allowed", target+"/exchange",
			"Users can auto-forward mail to arbitrary external addresses — the standard silent-exfil path after a mailbox takeover, and it survives a password reset. Disable automatic external forwarding with an outbound spam policy (SCuBA MS.EXO.1.1v2).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.7"}, PCI: []string{"3.4.1"}, HIPAA: []string{"164.312(e)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}, NIST80053: []string{"AC-4"}})))
	}
	if t.WeakMFAMethodsEnabled {
		f = append(f, finding(id(), "sspm::m365::weak-mfa-methods-enabled", types.SeverityHigh,
			"Phishable MFA methods (SMS / voice / email OTP) are enabled", target,
			"SMS, voice-call, and email one-time-passcode are permitted as MFA. All three are phishable in real time and SMS is SIM-swappable, so MFA is present but bypassable. Disable them and require phishing-resistant methods (FIDO2, Windows Hello, certificate) (SCuBA MS.AAD.3.5v2 / 3.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"6.3", "6.5"}, NISTCSF: []string{"PR.AC-7"}, NIST80053: []string{"IA-2"}})))
	}
	if t.RiskyUserBlockDisabled {
		f = append(f, finding(id(), "sspm::m365::risky-users-not-blocked", types.SeverityHigh,
			"Users flagged as high risk are not blocked", target,
			"Entra ID Protection has already classified these accounts as high risk (leaked credentials, anomalous behaviour) but no Conditional Access policy blocks them — the tenant detects the compromise and then permits it. Add a risk-based policy that blocks or forces secure password change (SCuBA MS.AAD.2.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC7.2"}, CISv8: []string{"6.7"}, NISTCSF: []string{"DE.CM-1", "PR.AC-7"}, NIST80053: []string{"AC-2", "SI-4"}})))
	}
	if t.RiskySignInBlockDisabled {
		f = append(f, finding(id(), "sspm::m365::risky-signins-not-blocked", types.SeverityHigh,
			"Sign-ins flagged as high risk are not blocked", target,
			"High-risk sign-ins (impossible travel, anonymous IP, malware-linked address) are allowed to complete. Add a sign-in-risk Conditional Access policy that blocks or requires MFA re-challenge (SCuBA MS.AAD.2.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC7.2"}, CISv8: []string{"6.7"}, NISTCSF: []string{"DE.CM-1", "PR.AC-7"}, NIST80053: []string{"AC-2", "SI-4"}})))
	}
	if t.UserAppRegistrationAllowed {
		f = append(f, finding(id(), "sspm::m365::user-app-registration-allowed", types.SeverityMedium,
			"Any user can register an application", target,
			"Non-admin users may register applications, giving an attacker with one mailbox a self-service route to an OAuth client that can then solicit consent (the illicit-consent-grant attack). Restrict app registration to administrators (SCuBA MS.AAD.5.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-6"}})))
	}
	if t.PermanentPrivilegedAssignments {
		f = append(f, finding(id(), "sspm::m365::permanent-privileged-roles", types.SeverityHigh,
			"Privileged roles are permanently active rather than just-in-time", target,
			"Highly privileged roles are held as permanent ACTIVE assignments instead of PIM-eligible. The privilege is standing, so an attacker inherits full admin the moment one of those accounts is taken over, with no activation step to detect. Convert them to eligible assignments requiring activation (SCuBA MS.AAD.7.4v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, PCI: []string{"7.2.1"}, HIPAA: []string{"164.312(a)(1)"}, CISv8: []string{"5.4", "6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2", "AC-6"}})))
	}
	if t.ExternalSenderWarningsDisabled {
		f = append(f, finding(id(), "sspm::m365::external-sender-warnings-disabled", types.SeverityMedium,
			"Inbound mail from outside the tenant is not tagged", target+"/exchange",
			"External-sender tagging is off, so a lookalike or impersonating sender arrives with no visual cue — the single cheapest anti-BEC control. Enable external sender identification (SCuBA MS.EXO.7.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, NISTCSF: []string{"PR.AT-1"}, NIST80053: []string{"SI-8"}})))
	}
	if t.AnyoneLinksNeverExpire || t.AnyoneLinkExpiryDays > 30 {
		detail := fmt.Sprintf("expire after %d days", t.AnyoneLinkExpiryDays)
		if t.AnyoneLinksNeverExpire {
			detail = "never expire"
		}
		f = append(f, finding(id(), "sspm::m365::anyone-link-expiry-too-long", types.SeverityMedium,
			"Anonymous 'Anyone' links "+detail, target+"/sharepoint",
			"Anonymous share links "+detail+", so any link that leaks (forwarded mail, an indexed page, a former employee's bookmarks) stays live indefinitely. Cap Anyone-link expiry at 30 days or less (SCuBA MS.SHAREPOINT.3.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if strings.EqualFold(t.DefaultSharingScope, "anyone") {
		f = append(f, finding(id(), "sspm::m365::default-sharing-scope-anyone", types.SeverityMedium,
			"New share links default to 'Anyone'", target+"/sharepoint",
			"The default audience for a new share link is anonymous 'Anyone', so a user leaks a document by accepting the default. Set the default scope to 'Specific people' (SCuBA MS.SHAREPOINT.2.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if strings.EqualFold(t.DefaultLinkPermission, "edit") {
		f = append(f, finding(id(), "sspm::m365::default-link-permission-edit", types.SeverityLow,
			"New share links default to edit permission", target+"/sharepoint",
			"Share links grant edit rights by default, so recipients who only need to read can also modify or delete. Default new links to view-only (SCuBA MS.SHAREPOINT.2.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if t.TeamsAnonymousStartMeeting {
		f = append(f, finding(id(), "sspm::m365::teams-anonymous-start-meeting", types.SeverityMedium,
			"Anonymous users can start Teams meetings", target+"/teams",
			"Unauthenticated users may START a meeting, not just join one — so an outsider can convene a meeting on the org's tenant and admit others, lending it the organisation's identity. Require an authenticated organiser (SCuBA MS.TEAMS.1.2v2).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-3"}, NIST80053: []string{"AC-3"}})))
	}
	return f
}
