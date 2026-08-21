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
	// APPLICATION CREDENTIALS. A service-principal secret or certificate is a credential
	// with no human attached: no MFA, no password reset, no offboarding. Lifetime is the
	// only control on it, which is why "how long" matters more here than anywhere else —
	// a five-year secret leaked in year one is an attacker's most durable asset in the
	// tenant. MS.AAD.5.5v1 / 5.6v1 / 5.7v1.
	AppPasswordAdditionAllowed bool `json:"app_password_addition_allowed,omitempty"`
	AppPasswordLifetimeDays    int  `json:"app_password_lifetime_days,omitempty"`
	AppCertificateLifetimeDays int  `json:"app_certificate_lifetime_days,omitempty"`
	// GUEST ACCESS. Guests are full directory principals with a foreign home tenant: the
	// account's password, MFA and lifecycle are administered by someone else entirely.
	// MS.AAD.8.1v1 / 8.2v1 / 8.3v1.
	//
	// GuestDirectoryAccessUnrestricted: guests can enumerate directory objects — users,
	// groups, memberships — which is the reconnaissance an attacker would otherwise have
	// to work for.
	GuestDirectoryAccessUnrestricted bool `json:"guest_directory_access_unrestricted,omitempty"`
	// AnyUserCanInviteGuests: invitation is not restricted to the Guest Inviter role, so
	// every member can add an externally-controlled principal to the tenant.
	AnyUserCanInviteGuests bool `json:"any_user_can_invite_guests,omitempty"`
	// GuestInvitesAnyDomain: no allowlist, so a guest may be invited from any domain
	// including a look-alike of a real partner.
	GuestInvitesAnyDomain bool `json:"guest_invites_any_domain,omitempty"`
	// DeviceCodeAuthAllowed: device-code flow is permitted. It is the current phishing
	// favourite because the victim sees a REAL Microsoft page and types a code they were
	// given — there is no fake domain to spot, and the attacker receives the tokens.
	// MS.AAD.3.9v1.
	DeviceCodeAuthAllowed bool `json:"device_code_auth_allowed,omitempty"`
	// SecurityLogsNotExported: sign-in and audit logs are not shipped anywhere. Entra
	// retains them for a limited window, so without export the evidence for an incident
	// discovered late has already expired. MS.AAD.4.1v1.
	SecurityLogsNotExported bool `json:"security_logs_not_exported,omitempty"`
	// PrivilegedAssignmentNoAlert / OtherPrivilegedActivationNoAlert complete the PIM
	// controls: 7.7 alerts on the ASSIGNMENT of a privileged role (eligible or active),
	// 7.9 on ACTIVATION of privileged roles other than Global Administrator.
	PrivilegedAssignmentNoAlert      bool `json:"privileged_assignment_no_alert,omitempty"`
	OtherPrivilegedActivationNoAlert bool `json:"other_privileged_activation_no_alert,omitempty"`
	// PrivilegedAccountsNotCloudOnly: privileged accounts are federated, so a compromise
	// of the on-premises directory is a compromise of tenant administration.
	// MS.AAD.7.3v1.
	PrivilegedAccountsNotCloudOnly bool `json:"privileged_accounts_not_cloud_only,omitempty"`
	// PRIVILEGED-ROLE GOVERNANCE (PIM). Standing Global Administrator is the single most
	// exploited weakness in a compromised M365 tenant: it needs no escalation, survives a
	// password reset it performs itself, and is indistinguishable from legitimate admin
	// work in the audit log. The four fields below are the controls that turn permanent
	// admin into borrowed admin. MS.AAD.7.2v1 / 7.5v1 / 7.6v1 / 7.8v1.
	//
	// StandingGlobalAdmins counts accounts holding Global Administrator PERMANENTLY
	// (as opposed to PIM-eligible). 0 = none or not supplied.
	StandingGlobalAdmins int `json:"standing_global_admins,omitempty"`
	// PrivilegedRolesOutsidePIM: highly privileged roles are assigned directly rather
	// than through PIM, so there is no activation record, no expiry and no approval.
	PrivilegedRolesOutsidePIM bool `json:"privileged_roles_outside_pim,omitempty"`
	// GlobalAdminActivationNoApproval / NoAlert: activating Global Administrator needs
	// nobody's approval, and raises no alert. Together these mean an attacker who can
	// activate an eligible role does so silently — the PIM control without the two
	// settings that make it observable.
	GlobalAdminActivationNoApproval bool `json:"global_admin_activation_no_approval,omitempty"`
	GlobalAdminActivationNoAlert    bool `json:"global_admin_activation_no_alert,omitempty"`
	// PasswordExpiryEnabled: forced rotation is advised AGAINST by CISA and NIST
	// SP 800-63B, so ENABLED is the finding — the same inversion as the Google
	// Workspace check. MS.AAD.6.1v1.
	PasswordExpiryEnabled bool `json:"password_expiry_enabled,omitempty"`
	// AdminConsentWorkflowDisabled: users who hit an app needing admin consent have no
	// route to request it, so the pressure is to grant consent broadly instead — the
	// workflow exists to make "ask an admin" cheaper than "let everyone consent".
	// MS.AAD.5.3v1.
	AdminConsentWorkflowDisabled bool `json:"admin_consent_workflow_disabled,omitempty"`
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
	// TeamsAutoAdmitAnonymous: anonymous participants and dial-in callers skip the lobby
	// entirely. The lobby is the ONLY point at which an uninvited attendee can be stopped,
	// so bypassing it means whoever holds a forwarded link is in the room.
	// MS.TEAMS.1.3v1.
	TeamsAutoAdmitAnonymous bool `json:"teams_auto_admit_anonymous,omitempty"`
	// TeamsDialInBypassLobby: dial-in callers specifically bypass the lobby. Separate from
	// the above because it is a separate setting with a separate owner, and a tenant can
	// have one without the other. MS.TEAMS.1.5v1.
	TeamsDialInBypassLobby bool `json:"teams_dial_in_bypass_lobby,omitempty"`
	// TeamsExternalControlRequest: external participants may request control of a shared
	// screen — handing an outsider the presenter's desktop. MS.TEAMS.1.1v1.
	TeamsExternalControlRequest bool `json:"teams_external_control_request,omitempty"`
	// TeamsEmailIntegrationEnabled: anyone who learns a channel's email address can post
	// into it, which is an unauthenticated content-injection and phishing path into a
	// trusted internal surface. The one SHALL in this group. MS.TEAMS.4.1v1.
	TeamsEmailIntegrationEnabled bool `json:"teams_email_integration_enabled,omitempty"`
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
	if n := appCredentialGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::m365::app-credential-lifetime", types.SeverityMedium,
			"Application credentials are long-lived or unrestricted ("+strings.Join(n, ", ")+")", target+"/entra",
			"Application credentials are the only kind with no human attached: no MFA, no password reset, no "+
				"offboarding. "+strings.Join(n, ", ")+". Lifetime is the sole control on them, so a multi-year "+
				"secret leaked early becomes an attacker's most durable asset in the tenant — one that survives "+
				"every user-side remediation. Restrict application password and certificate lifetimes "+
				"(SCuBA MS.AAD.5.5v1–5.7v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"5.4", "6.8"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if n := guestGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::m365::guest-access-unrestricted", types.SeverityMedium,
			"Guest access is unrestricted ("+strings.Join(n, ", ")+")", target+"/entra",
			"Guests are full directory principals whose password, MFA and lifecycle are administered by "+
				"another tenant entirely. "+strings.Join(n, ", ")+". Unrestricted directory read gives a guest "+
				"the user, group and membership map an attacker would otherwise have to work for. Restrict "+
				"guest directory access, invitation rights and permitted domains "+
				"(SCuBA MS.AAD.8.1v1–8.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2", "AC-6"}})))
	}
	if t.DeviceCodeAuthAllowed {
		f = append(f, finding(id(), "sspm::m365::device-code-auth-allowed", types.SeverityHigh,
			"Device-code authentication is permitted", target+"/entra",
			"The device-code flow is the current phishing favourite precisely because it defeats the advice "+
				"users are given: the victim sees a REAL Microsoft sign-in page at a real Microsoft domain and "+
				"enters a code someone sent them. There is no look-alike URL to notice, and the attacker "+
				"receives the resulting tokens. Block device-code authentication except where a device "+
				"genuinely needs it (SCuBA MS.AAD.3.9v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2"}})))
	}
	if t.SecurityLogsNotExported {
		f = append(f, finding(id(), "sspm::m365::security-logs-not-exported", types.SeverityHigh,
			"Sign-in and audit logs are not exported for monitoring", target+"/entra",
			"Entra retains sign-in and audit logs for a limited window and they are not being shipped "+
				"anywhere. Incidents are routinely discovered weeks after the fact, so without export the "+
				"evidence needed to answer what happened has already expired by the time anyone asks. Export "+
				"security logs to a monitored destination (SCuBA MS.AAD.4.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, PCI: []string{"10.5.1"}, CISv8: []string{"8.2", "8.9"}, NISTCSF: []string{"DE.CM-1"}, NIST80053: []string{"AU-6", "AU-9"}})))
	}
	if t.PrivilegedAssignmentNoAlert {
		f = append(f, finding(id(), "sspm::m365::privileged-assignment-no-alert", types.SeverityMedium,
			"Privileged role assignments raise no alert", target+"/entra",
			"Granting a highly privileged role — eligible or active — notifies nobody. Assignment is the step "+
				"an attacker takes to make access durable, and it is the one moment the change is still cheap "+
				"to reverse. Alert on privileged role assignment (SCuBA MS.AAD.7.7v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, CISv8: []string{"8.11"}, NISTCSF: []string{"DE.CM-1"}, NIST80053: []string{"AU-6", "SI-4"}})))
	}
	if t.OtherPrivilegedActivationNoAlert {
		f = append(f, finding(id(), "sspm::m365::other-privileged-activation-no-alert", types.SeverityLow,
			"Activation of privileged roles other than Global Administrator raises no alert", target+"/entra",
			"Only Global Administrator activation is watched. Exchange, SharePoint and User Administrator "+
				"each reach most of what an attacker wants and attract none of the attention, which is why a "+
				"careful one takes those instead. Alert on activation of all highly privileged roles "+
				"(SCuBA MS.AAD.7.9v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, CISv8: []string{"8.11"}, NISTCSF: []string{"DE.CM-1"}, NIST80053: []string{"AU-6"}})))
	}
	if t.PrivilegedAccountsNotCloudOnly {
		f = append(f, finding(id(), "sspm::m365::privileged-accounts-not-cloud-only", types.SeverityMedium,
			"Privileged accounts are federated rather than cloud-only", target+"/entra",
			"Privileged accounts authenticate through an on-premises or third-party identity provider, so a "+
				"compromise of that directory is a compromise of tenant administration — and the assumption "+
				"that cloud admin survives an on-premises incident, which every break-glass plan rests on, "+
				"stops holding. Provision privileged accounts cloud-only (SCuBA MS.AAD.7.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"5.4"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2", "AC-6"}})))
	}
	if t.StandingGlobalAdmins > 0 {
		f = append(f, finding(id(), "sspm::m365::standing-global-admin", types.SeverityHigh,
			fmt.Sprintf("%d account(s) hold Global Administrator permanently", t.StandingGlobalAdmins), target+"/entra",
			fmt.Sprintf("%d account(s) hold Global Administrator as a STANDING assignment rather than "+
				"activating it through PIM when needed. Standing global admin is the most valuable thing in "+
				"the tenant: it needs no escalation, it survives a password reset it performs itself, and its "+
				"use is indistinguishable from legitimate admin work in the log. Move these to PIM-eligible "+
				"and assign finer-grained roles for day-to-day work (SCuBA MS.AAD.7.2v1).", t.StandingGlobalAdmins),
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"5.4", "6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2", "AC-6"}})))
	}
	if t.PrivilegedRolesOutsidePIM {
		f = append(f, finding(id(), "sspm::m365::privileged-roles-outside-pim", types.SeverityHigh,
			"Highly privileged roles are assigned outside PIM", target+"/entra",
			"Privileged roles are granted directly rather than through Privileged Identity Management, so "+
				"there is no activation record, no expiry and no approval step. The grant is permanent and the "+
				"only evidence it was used is whatever the role itself logs. Provision highly privileged roles "+
				"through PIM (SCuBA MS.AAD.7.5v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"5.4", "6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2", "AC-6"}})))
	}
	if t.GlobalAdminActivationNoApproval {
		f = append(f, finding(id(), "sspm::m365::global-admin-activation-no-approval", types.SeverityMedium,
			"Global Administrator activation requires no approval", target+"/entra",
			"An account eligible for Global Administrator can activate it unilaterally. PIM's value is that "+
				"someone else has to agree — without approval it is a delay, not a control, and an attacker "+
				"holding an eligible account simply waits it out. Require approval for Global Administrator "+
				"activation (SCuBA MS.AAD.7.6v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"5.4"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2"}})))
	}
	if t.GlobalAdminActivationNoAlert {
		f = append(f, finding(id(), "sspm::m365::global-admin-activation-no-alert", types.SeverityMedium,
			"Global Administrator activation raises no alert", target+"/entra",
			"Nobody is notified when Global Administrator is activated. This is the one event in the tenant "+
				"most worth watching, and an activation an attacker performs looks exactly like one an "+
				"administrator performs — the difference is only that somebody noticed. Enable alerting on "+
				"Global Administrator activation (SCuBA MS.AAD.7.8v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, CISv8: []string{"8.11"}, NISTCSF: []string{"DE.CM-1"}, NIST80053: []string{"AU-6", "SI-4"}})))
	}
	if t.PasswordExpiryEnabled {
		f = append(f, finding(id(), "sspm::m365::password-expiry-enabled", types.SeverityLow,
			"Passwords are configured to expire", target+"/entra",
			"Forced password rotation is now advised AGAINST by both CISA and NIST SP 800-63B: it drives "+
				"users to predictable increments and to writing passwords down, which costs more than the "+
				"compromise window it shortens. Set passwords never to expire and rely on strength, "+
				"reuse-blocking and MFA (SCuBA MS.AAD.6.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.AdminConsentWorkflowDisabled {
		f = append(f, finding(id(), "sspm::m365::admin-consent-workflow-disabled", types.SeverityMedium,
			"No admin consent workflow is configured", target+"/entra",
			"Users who hit an application needing administrator consent have no way to request it, so the "+
				"pressure is on the tenant to allow broad user consent instead. The workflow exists to make "+
				"asking an admin cheaper than letting everyone decide. Configure an admin consent workflow "+
				"(SCuBA MS.AAD.5.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-6"}})))
	}
	if t.TeamsEmailIntegrationEnabled {
		f = append(f, finding(id(), "sspm::m365::teams-email-integration-enabled", types.SeverityMedium,
			"Teams channel email integration is enabled", target+"/teams",
			"Channels accept mail at a generated address, so anyone who learns or guesses it can post into a "+
				"channel your staff read as internal — an unauthenticated route for phishing and malware into a "+
				"trusted surface, with none of the sender checks inbound mail gets. Disable Teams email "+
				"integration (SCuBA MS.TEAMS.4.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"9.6"}, NISTCSF: []string{"PR.DS-5"}, NIST80053: []string{"SC-7"}})))
	}
	if t.TeamsAutoAdmitAnonymous {
		f = append(f, finding(id(), "sspm::m365::teams-auto-admit-anonymous", types.SeverityMedium,
			"Anonymous and dial-in participants skip the Teams lobby", target+"/teams",
			"The lobby is the only point at which an uninvited attendee can be stopped. With auto-admit on, "+
				"whoever holds a forwarded invite is in the room — and in a recorded meeting, in the recording. "+
				"Require anonymous and dial-in participants to wait in the lobby (SCuBA MS.TEAMS.1.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-3"}, NIST80053: []string{"AC-3"}})))
	}
	if t.TeamsDialInBypassLobby {
		f = append(f, finding(id(), "sspm::m365::teams-dial-in-bypass-lobby", types.SeverityLow,
			"Dial-in callers bypass the Teams lobby", target+"/teams",
			"A caller on the phone bridge joins without being admitted. Dial-in identity is a phone number at "+
				"best, so this is the least-verified way into a meeting and the one least likely to be noticed. "+
				"Disable dial-in lobby bypass (SCuBA MS.TEAMS.1.5v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-3"}})))
	}
	if t.TeamsExternalControlRequest {
		f = append(f, finding(id(), "sspm::m365::teams-external-control-request", types.SeverityMedium,
			"External participants can request control of a shared screen", target+"/teams",
			"An outside participant can ask for control of a presenter's desktop, and a presenter mid-demo "+
				"clicks accept. That is remote interactive access to a corporate endpoint obtained by asking "+
				"politely. Block external control requests (SCuBA MS.TEAMS.1.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-3"}, NIST80053: []string{"AC-3"}})))
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

// appCredentialGapsOf names which application-credential controls are loose. CISA's
// thresholds: passwords 180 days, certificates 365. A zero lifetime means unbounded, not
// unset — the field is only populated when the tenant reports one.
func appCredentialGapsOf(t M365Tenant) []string {
	var n []string
	if t.AppPasswordAdditionAllowed {
		n = append(n, "application password addition is allowed")
	}
	if t.AppPasswordLifetimeDays > 180 {
		n = append(n, fmt.Sprintf("password lifetime %d days", t.AppPasswordLifetimeDays))
	}
	if t.AppCertificateLifetimeDays > 365 {
		n = append(n, fmt.Sprintf("certificate lifetime %d days", t.AppCertificateLifetimeDays))
	}
	return n
}

// guestGapsOf names which guest controls are open.
func guestGapsOf(t M365Tenant) []string {
	var n []string
	if t.GuestDirectoryAccessUnrestricted {
		n = append(n, "guests can read directory objects")
	}
	if t.AnyUserCanInviteGuests {
		n = append(n, "any member can invite guests")
	}
	if t.GuestInvitesAnyDomain {
		n = append(n, "guests may be invited from any domain")
	}
	return n
}
