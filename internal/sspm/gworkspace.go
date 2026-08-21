package sspm

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// GWorkspaceTenant is a grounded snapshot of a Google Workspace tenant's COLLABORATION / DATA-SHARING posture —
// the Drive / Gmail / Calendar / app-access settings that expose corporate data. DISTINCT from the Google
// Workspace IDENTITY posture (MFA/2SV, OAuth grants, stale accounts) the `operate` engine already covers: it
// closes the SSPM gap where we did Google's identity half but not its Drive/Gmail data-sharing half. With M365
// (`m365.go`), these are the two most-common SaaS estates. Sourced from the Google Admin SDK / Drive API (the
// credential-gated half — reuses the onboarded Google token) or a posted snapshot. Snapshot-driven, LLM-free,
// grounded: a hardened tenant yields zero findings. Reuses the package finding/comp helpers.
type GWorkspaceTenant struct {
	Name string `json:"name"`
	// Drive external-sharing level: "public" (Anyone on the internet — anonymous) | "external" (any external
	// user) | "domains" (allowlisted) | "restricted" (off). "public" is the worst.
	DriveSharing             string `json:"drive_sharing"`
	DriveExternalAllowlist   bool   `json:"drive_external_allowlist"`   // external Drive sharing limited to allowlisted domains
	DriveLinkSharingDefault  bool   `json:"drive_link_sharing_default"` // new files default to link-sharing (anyone-with-link)
	LessSecureAppsEnabled    bool   `json:"less_secure_apps_enabled"`   // legacy "less secure app" access (password basic-auth, MFA-bypass)
	ThirdPartyAPIAccess      bool   `json:"third_party_api_access"`     // any third-party OAuth app can access data (no app allowlist / API controls)
	GmailExternalAutoForward bool   `json:"gmail_external_autoforward"` // users may auto-forward mail to external addresses (exfil)
	ExternalCalendarSharing  bool   `json:"external_calendar_sharing"`  // calendar details shared with external/public
	// FormsAcceptExternalResponses / FormsSubmitExternally: Forms carries data in and out
	// of the organisation while looking like a document rather than a channel, so it
	// routinely sits outside whatever sharing policy the estate actually has.
	// GWS.DRIVEDOCS.1.10v1 / 1.11v1.
	FormsAcceptExternalResponses bool `json:"forms_accept_external_responses,omitempty"`
	FormsSubmitExternally        bool `json:"forms_submit_externally,omitempty"`
	// SharedDriveCreationOverridable: members with manager access can override the
	// organisation's shared-drive creation settings, which makes the org-level policy a
	// default rather than a control — anyone with manager on any drive can opt out of it.
	// GWS.DRIVEDOCS.2.1v1.
	SharedDriveCreationOverridable bool `json:"shared_drive_creation_overridable,omitempty"`
	// NonMembersCannotBeAddedToFiles INVERTS, and is the third inversion in this
	// catalogue after password expiry and the Teams lobby. CISA requires that agencies
	// SHALL ALLOW non-members to be added to individual files, because BLOCKING it does
	// not stop the sharing — it makes people copy the file OUT of the shared drive to
	// share it, which loses the shared drive's access controls, audit trail and retention
	// in one move. The permissive setting is the safer one. GWS.DRIVEDOCS.2.2v1.
	NonMembersCannotBeAddedToFiles bool `json:"non_members_cannot_be_added_to_files,omitempty"`
	// PostSSOVerificationOff: after an SSO assertion Google performs no additional check,
	// so anyone who can produce an assertion — including via a compromised IdP — lands
	// straight in. SSO concentrates trust in one system; post-SSO verification is the only
	// control that does not. GWS.COMMONCONTROLS.3.1v1 (own profile) / 3.2v1 (others).
	PostSSOVerificationOff      bool `json:"post_sso_verification_off,omitempty"`
	PostSSOVerificationOffOther bool `json:"post_sso_verification_off_other,omitempty"`
	// UnassessedServicesEnabled: Google services with no individual admin control are ON
	// by default, so every service Google ships is enabled the day it ships without anyone
	// deciding. The named ones below are the same failure with a name.
	// GWS.COMMONCONTROLS.16.1v1 / 16.2v1 / 16.3v1 / 16.4v1.
	UnassessedServicesEnabled bool `json:"unassessed_services_enabled,omitempty"`
	EarlyAccessAppsEnabled    bool `json:"early_access_apps_enabled,omitempty"`
	LookerStudioExternalShare bool `json:"looker_studio_external_share,omitempty"`
	PinpointDriveAccess       bool `json:"pinpoint_drive_access,omitempty"`
	// RecoveryInfoAllowed: users may add their own recovery phone or address, which is a
	// self-service password-reset channel whose security is a personal mailbox or a
	// portable phone number. GWS.COMMONCONTROLS.8.3v1.
	RecoveryInfoAllowed bool `json:"recovery_info_allowed,omitempty"`
	// AccountConflictUnmanaged: personal Google accounts created on the corporate domain
	// are left as conflicting UNMANAGED accounts rather than being absorbed. They hold
	// company data, answer to nobody's admin console, and survive offboarding entirely.
	// GWS.COMMONCONTROLS.7.1v1.
	AccountConflictUnmanaged bool `json:"account_conflict_unmanaged,omitempty"`
	// PhishingResistant2SVNotEnforced: 2SV is required but any method counts, including a
	// code. Only a security key is bound to the origin and survives an
	// adversary-in-the-middle proxy — "2SV is on" is a weaker claim than "2SV cannot be
	// phished", which is why CISA writes them as separate policies.
	// GWS.COMMONCONTROLS.1.1v1.
	PhishingResistant2SVNotEnforced bool `json:"phishing_resistant_2sv_not_enforced,omitempty"`
	// UnconfiguredThirdPartyAppsAllowed is the THIRD-PARTY twin of
	// UnconfiguredInternalAppsTrusted: apps nobody has reviewed, from outside the domain
	// entirely. GWS.COMMONCONTROLS.10.4v1.
	UnconfiguredThirdPartyAppsAllowed bool `json:"unconfigured_third_party_apps_allowed,omitempty"`
	// DriveSDKEnabled: the Drive SDK lets a third-party application read and write Drive
	// through the API. Distinct from general app access because it reaches the FILES
	// rather than the account. GWS.DRIVEDOCS.4.1v1.
	DriveSDKEnabled bool `json:"drive_sdk_enabled,omitempty"`
	// POPIMAPEnabled: POP and IMAP authenticate with a password alone and stream an entire
	// mailbox. After an account compromise this is how the mail actually leaves — it is
	// the exfiltration step, not the entry. Distinct from less-secure-apps, which is a
	// broader toggle. GWS.GMAIL.9.1v1.
	POPIMAPEnabled bool `json:"pop_imap_enabled,omitempty"`
	// SecondaryCalendarExternalSharing: secondary calendars share separately from the
	// primary one, and are where project and interview schedules usually live — so the
	// calendar most worth reading is the one the primary setting does not cover.
	// GWS.CALENDAR.1.2v1.
	SecondaryCalendarExternalSharing bool `json:"secondary_calendar_external_sharing,omitempty"`
	// CalendarInteropEnabled / CalendarInteropBasicAuth: Calendar Interop shares free/busy
	// with an external Exchange organisation. The SHALL is not about interop itself but
	// about HOW it authenticates: basic auth means a standing credential, replayable and
	// unprotected by MFA, held by another organisation's mail system.
	// GWS.CALENDAR.3.1v1 / 3.2v1.
	CalendarInteropEnabled   bool `json:"calendar_interop_enabled,omitempty"`
	CalendarInteropBasicAuth bool `json:"calendar_interop_basic_auth,omitempty"`
	// AppointmentPaymentsEnabled: appointment scheduling can take payments, which puts a
	// payment flow — and the compliance scope that follows it — inside a calendar feature
	// nobody assessed as a payment system. GWS.CALENDAR.4.1v1.
	AppointmentPaymentsEnabled bool `json:"appointment_payments_enabled,omitempty"`
	// SPOOFING PROTECTION. Three settings, one control, and the one that matters most for
	// business-email compromise: 7.1 catches look-alike DOMAINS, 7.2 catches a display
	// name impersonating an employee (the CEO-fraud shape, which needs no domain trick at
	// all), 7.5 stops inbound mail spoofing your own domain into your Groups.
	// GWS.GMAIL.7.1v1 / 7.2v1 / 7.5v1.
	SimilarDomainSpoofProtectionOff bool `json:"similar_domain_spoof_protection_off,omitempty"`
	EmployeeNameSpoofProtectionOff  bool `json:"employee_name_spoof_protection_off,omitempty"`
	GroupsSpoofProtectionOff        bool `json:"groups_spoof_protection_off,omitempty"`
	// AUTO-APPLY. Google ships new mail protections continuously; with auto-apply off a
	// tenant's defences are frozen at whatever was configured on the day someone last
	// looked. This is the setting that decides whether posture DECAYS.
	// GWS.GMAIL.6.4v1 / 7.7v1.
	LinkAutoApplyOff  bool `json:"link_auto_apply_off,omitempty"`
	SpoofAutoApplyOff bool `json:"spoof_auto_apply_off,omitempty"`
	// PreDeliveryScanningOff: enhanced pre-delivery scanning is disabled, so suspicious
	// mail is assessed only after it is already sitting in the mailbox.
	// GWS.GMAIL.15.1v1.
	PreDeliveryScanningOff bool `json:"pre_delivery_scanning_off,omitempty"`
	// UserEmailUploadsEnabled: users may upload mail from outside into Workspace,
	// introducing files that never passed the inbound filters at all. GWS.GMAIL.8.1v1.
	UserEmailUploadsEnabled bool `json:"user_email_uploads_enabled,omitempty"`
	// ExternalOutboundGateway: outbound mail may be routed through a non-Google server.
	// Whoever runs that server reads everything the organisation sends, and can alter it,
	// with nothing in Workspace's own logs to show for it. GWS.GMAIL.12.1v1.
	ExternalOutboundGateway bool `json:"external_outbound_gateway,omitempty"`
	// SpamBypassAllSenders: the org-wide toggle that bypasses spam filtering and hides
	// warnings for ALL senders — distinct from a per-domain bypass list, and far worse,
	// because it removes the warnings a user would otherwise still see. GWS.GMAIL.18.3v1.
	SpamBypassAllSenders bool `json:"spam_bypass_all_senders,omitempty"`
	// MailDelegationEnabled: users may grant others full mailbox access. Delegation
	// survives the delegate changing role and is rarely reviewed. GWS.GMAIL.1.1v1.
	MailDelegationEnabled bool `json:"mail_delegation_enabled,omitempty"`
	// SESSION AND DEVICE TRUST. Two settings that decide how long a stolen credential
	// keeps working, which is usually a bigger question than how it was stolen.
	//
	// DeviceTrustAllowed: users may mark a device trusted and skip 2-step verification on
	// it. That is an MFA bypass the user grants themselves, and it survives the password
	// reset performed after a compromise. GWS.COMMONCONTROLS.1.5v1.
	DeviceTrustAllowed bool `json:"device_trust_allowed,omitempty"`
	// SessionNeverExpires: no forced re-authentication, so a session cookie lifted from a
	// browser works indefinitely. Session length is the difference between an incident and
	// a persistent foothold. GWS.COMMONCONTROLS.4.1v1.
	SessionNeverExpires bool `json:"session_never_expires,omitempty"`
	// TwoSVEnrollmentPeriodDays: the grace window in which a new user may sign in WITHOUT
	// enrolling in 2SV. Every day of it is a window in which a freshly-provisioned account
	// — the ones whose credentials are most often mishandled during onboarding — has one
	// factor. 0 = not supplied. GWS.COMMONCONTROLS.1.4v1.
	TwoSVEnrollmentPeriodDays int `json:"twosv_enrollment_period_days,omitempty"`
	// APP CONSENT. UserConsentLowRiskScopes: users may grant third-party apps access to
	// "low-risk" scopes without review — but low-risk is Google's judgement about the
	// SCOPE, not about the app holding it, and the grant is standing.
	// GWS.COMMONCONTROLS.10.2v1.
	UserConsentLowRiskScopes bool `json:"user_consent_low_risk_scopes,omitempty"`
	// UnconfiguredInternalAppsTrusted: apps from inside the domain are trusted by default
	// without being configured. "Internal" is a property of who registered it, not of who
	// controls it now. GWS.COMMONCONTROLS.10.3v1.
	UnconfiguredInternalAppsTrusted bool `json:"unconfigured_internal_apps_trusted,omitempty"`
	// TakeoutEnabled: any user can export their entire Workspace data — mail, Drive,
	// calendar — as a downloadable archive. It is a one-click bulk-exfiltration channel
	// that produces no alert and looks like a legitimate user action, which is exactly why
	// a compromised account reaches for it. GWS.COMMONCONTROLS.12.1v1.
	TakeoutEnabled bool `json:"takeout_enabled,omitempty"`
	// AdminAccountsNotCloudOnly: administrative accounts are federated from an on-premises
	// or third-party identity source, so a compromise of THAT directory is a compromise of
	// Workspace admin — the cloud tenant inherits the weakest link of a system it does not
	// control. GWS.COMMONCONTROLS.6.1v1.
	AdminAccountsNotCloudOnly bool `json:"admin_accounts_not_cloud_only,omitempty"`
	// DRIVE SHARING WARNINGS. Two settings, one control: does a user get told before a
	// file leaves the organisation. 1.3 warns at share time when the recipient's domain is
	// not allowlisted; 1.9 warns at the file level for out-of-domain access. Both are the
	// last moment a mistake is still cheap to undo.
	// GWS.DRIVEDOCS.1.3v1 / 1.9v1.
	DriveExternalShareWarningsDisabled bool `json:"drive_external_share_warnings_disabled,omitempty"`
	DriveOutOfDomainWarningsDisabled   bool `json:"drive_out_of_domain_warnings_disabled,omitempty"`
	// DriveSecurityUpdateNotApplied: Google's Drive security update adds a resource key to
	// sharing links. WITHOUT it, links created before the change remain in the old
	// guessable format — so a link that leaked years ago, or was enumerated, still works.
	// This is the rare posture setting that is retroactive: applying it invalidates old
	// exposure rather than only preventing new. GWS.DRIVEDOCS.3.1v1.
	DriveSecurityUpdateNotApplied bool `json:"drive_security_update_not_applied,omitempty"`
	// DriveRansomwareMonitoringDisabled: Drive can detect the mass-corruption signature of
	// ransomware encrypting a synced folder. Without it the first sign is a user noticing,
	// by which point the sync has already propagated the encryption to everyone sharing
	// the drive. GWS.DRIVEDOCS.5.2v1.
	DriveRansomwareMonitoringDisabled bool `json:"drive_ransomware_monitoring_disabled,omitempty"`
	// DriveNonGoogleAccountSharing: files may be shared with recipients who have no Google
	// account, via a link plus an emailed PIN. The recipient is unauthenticated in any
	// sense we can audit. GWS.DRIVEDOCS.1.4v1.
	DriveNonGoogleAccountSharing bool `json:"drive_non_google_account_sharing,omitempty"`
	// DriveExternalSharedDriveUpload: users may move content INTO a shared drive owned by
	// another organisation — an exfiltration path that looks like ordinary collaboration
	// and leaves the file under someone else's retention and access control.
	// GWS.DRIVEDOCS.1.7v1.
	DriveExternalSharedDriveUpload bool `json:"drive_external_shared_drive_upload,omitempty"`
	// ExternalInviteWarningsDisabled: no prompt before sending an invitation outside the
	// org. The warning is what catches a mistyped domain or a look-alike one BEFORE the
	// invite carries a meeting link and an attendee list out of the company.
	// GWS.CALENDAR.2.1v1.
	ExternalInviteWarningsDisabled bool `json:"external_invite_warnings_disabled,omitempty"`

	// --- Fields below close mandatory (SHALL) gaps found by the CISA SCuBA neutral
	// benchmark (internal/bench/scuba.go), mirroring the M365 set in m365.go. Every
	// field is OPTIONAL and named so that TRUE (or a supplied number) is the
	// VIOLATION — the zero value means "not supplied", so a legacy snapshot gains no
	// findings and absence is never read as insecurity.

	// WeakMFAMethodsEnabled: SMS or voice is permitted as a 2SV method — phishable
	// and SIM-swappable. GWS.COMMONCONTROLS.1.3v1.
	WeakMFAMethodsEnabled bool `json:"weak_mfa_methods_enabled,omitempty"`
	// SuperAdminSelfRecoveryEnabled / UserSelfRecoveryEnabled: account self-recovery
	// is on, letting an attacker who controls a recovery channel (phone, personal
	// mail) reset their way in. GWS.COMMONCONTROLS.8.1v1 / 8.2v1.
	SuperAdminSelfRecoveryEnabled bool `json:"super_admin_self_recovery_enabled,omitempty"`
	UserSelfRecoveryEnabled       bool `json:"user_self_recovery_enabled,omitempty"`
	// PasswordMinLength: enforced minimum password length. 0 = not supplied; 1..11
	// is below the baseline. GWS.COMMONCONTROLS.5.2v1.
	PasswordMinLength int `json:"password_min_length,omitempty"`
	// PasswordStrengthNotEnforced: the strength requirement is off entirely.
	// GWS.COMMONCONTROLS.5.1v1.
	PasswordStrengthNotEnforced bool `json:"password_strength_not_enforced,omitempty"`
	// PasswordPolicyNotEnforcedAtSignIn: a changed policy applies only to NEW passwords,
	// so every account that does not voluntarily rotate keeps the weak one indefinitely —
	// the setting turns a policy into a suggestion. GWS.COMMONCONTROLS.5.4v1.
	PasswordPolicyNotEnforcedAtSignIn bool `json:"password_policy_not_enforced_at_signin,omitempty"`
	// PasswordReuseAllowed: users may set a password they have used before, which
	// re-arms every credential already sitting in a breach dump.
	// GWS.COMMONCONTROLS.5.5v1.
	PasswordReuseAllowed bool `json:"password_reuse_allowed,omitempty"`
	// PasswordExpiryDays: forced rotation, in days. 0 = none, which is what CISA and
	// NIST both now REQUIRE — expiry drives users to predictable increments and is a
	// net loss. Non-zero is the finding here, which is the opposite of the intuition
	// most password checks encode. GWS.COMMONCONTROLS.5.6v1.
	PasswordExpiryDays int `json:"password_expiry_days,omitempty"`
	// SpamBypassDomains: how many domains sit on a spam-filter bypass list. Any is a
	// hole straight to the inbox. GWS.GMAIL.18.1v1.
	SpamBypassDomains int `json:"spam_bypass_domains,omitempty"`
	// DriveAccessCheckingLoose: link access-checking is wider than "recipients
	// only", so a forwarded link works for whoever holds it. GWS.DRIVEDOCS.1.6v1.
	DriveAccessCheckingLoose bool `json:"drive_access_checking_loose,omitempty"`
	// ExternalReplyWarningsDisabled: no warning when replying outside the org.
	// GWS.GMAIL.13.1v1.
	ExternalReplyWarningsDisabled bool `json:"external_reply_warnings_disabled,omitempty"`
	// InboundSpoofProtectionDisabled / UnauthenticatedEmailProtectionDisabled: Gmail
	// is not rejecting mail that spoofs the org's own domain, nor mail that fails
	// authentication outright. GWS.GMAIL.7.3v1 / 7.4v1.
	InboundSpoofProtectionDisabled bool `json:"inbound_spoof_protection_disabled,omitempty"`
	// AttachmentProtectionDisabled: Gmail's advanced attachment scanning is off —
	// encrypted attachments, attachments carrying scripts, and anomalous types from
	// untrusted senders all pass to the inbox unexamined. These are three settings in the
	// admin console and ONE control in practice, because an attacker only needs whichever
	// one is off; the snapshot carries them separately so the finding can say which.
	// GWS.GMAIL.5.1v1 / 5.2v1 / 5.3v1.
	EncryptedAttachmentProtectionDisabled bool `json:"encrypted_attachment_protection_disabled,omitempty"`
	ScriptAttachmentProtectionDisabled    bool `json:"script_attachment_protection_disabled,omitempty"`
	AnomalousAttachmentProtectionDisabled bool `json:"anomalous_attachment_protection_disabled,omitempty"`
	// LinkProtectionDisabled: the link half of the same defence — shortened URLs are not
	// expanded, linked images are not scanned, and no warning is shown on a click through
	// to an untrusted domain. A shortener is the cheapest way to put a known-bad
	// destination past a filter that only reads the visible text.
	// GWS.GMAIL.6.1v1 / 6.2v1 / 6.3v1.
	ShortenedURLScanDisabled bool `json:"shortened_url_scan_disabled,omitempty"`
	LinkedImageScanDisabled  bool `json:"linked_image_scan_disabled,omitempty"`
	UntrustedLinkWarningsOff bool `json:"untrusted_link_warnings_off,omitempty"`
	// SuspiciousMailKeptInInbox: mail the above protections FLAG is still delivered to the
	// inbox rather than quarantined. This is the setting that decides whether the other
	// six do anything: a detection that lands in front of the user is a warning label on a
	// weapon they are already holding. GWS.GMAIL.5.4v1 / 7.6v1.
	SuspiciousMailKeptInInbox              bool `json:"suspicious_mail_kept_in_inbox,omitempty"`
	UnauthenticatedEmailProtectionDisabled bool `json:"unauthenticated_email_protection_disabled,omitempty"`
	// WorkspaceSyncEnabled: Google Workspace Sync for Microsoft Outlook (GWSMO) is on,
	// which keeps a full local replica of mail, calendar and contacts in an Outlook
	// profile. The copy sits outside every Workspace-side control — DLP does not see it,
	// revoking the account does not reach it, and the offboarding checklist does not know
	// it exists. GWS.GMAIL.10.1v1.
	WorkspaceSyncEnabled bool `json:"workspace_sync_enabled,omitempty"`
	// EmailAllowlistImplemented INVERTS the usual intuition, and is the fourth inversion
	// in this catalogue. An allowlist reads as a hardening control, but Gmail's email
	// allowlist does not grant access — it EXEMPTS the listed senders from spam and
	// phishing filtering entirely. Every address on it is a sender whose mail arrives
	// unexamined, and the addresses that end up there are the trusted partners and
	// vendors an attacker most wants to impersonate. Distinct from the spam-bypass
	// domain list (18.1v1), which is a separate admin setting. GWS.GMAIL.14.1v1.
	EmailAllowlistImplemented bool `json:"email_allowlist_implemented,omitempty"`
	// SecuritySandboxDisabled: attachments are not detonated in a sandbox before
	// delivery, so an attachment is judged on signatures and reputation alone. This is
	// the check that catches the payload nobody has seen before, which is the only kind
	// a targeted attack sends. GWS.GMAIL.16.1v1.
	SecuritySandboxDisabled bool `json:"security_sandbox_disabled,omitempty"`
	// ComprehensiveMailStorageDisabled: mail from non-Gmail Workspace applications is not
	// stored in the associated user's mailbox, so it never reaches Vault, eDiscovery,
	// retention or a mailbox export. The loss is invisible until an investigation or a
	// legal hold needs the message and finds it was never kept. GWS.GMAIL.17.1v1.
	ComprehensiveMailStorageDisabled bool `json:"comprehensive_mail_storage_disabled,omitempty"`
}

// AssessGoogleWorkspace runs every grounded collaboration/data-sharing posture check over a Google Workspace
// snapshot. A securely configured tenant returns nil.
func AssessGoogleWorkspace(t GWorkspaceTenant, opts Options) []types.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-gworkspace-%03d", n) }
	target := "google_workspace:" + t.Name

	var f []types.Finding
	if strings.EqualFold(t.DriveSharing, "public") {
		f = append(f, finding(id(), "sspm::google_workspace::drive-public-sharing", types.SeverityHigh,
			"Drive allows public ('Anyone on the internet') sharing", target+"/drive",
			"Drive sharing is set to 'Anyone on the internet' — anonymous, unauthenticated links to corporate documents. Restrict Drive external sharing to 'Off' or allowlisted domains.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, PCI: []string{"7.2.1"}, HIPAA: []string{"164.312(a)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if strings.EqualFold(t.DriveSharing, "external") && !t.DriveExternalAllowlist {
		f = append(f, finding(id(), "sspm::google_workspace::drive-external-no-allowlist", types.SeverityMedium,
			"Drive external sharing is not restricted to allowlisted domains", target+"/drive",
			"Drive can be shared with any external user. Restrict external sharing to an allowlist of trusted partner domains so corporate data can't leave to arbitrary accounts.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, GDPR: []string{"Art. 32"}})))
	}
	if t.DriveLinkSharingDefault {
		f = append(f, finding(id(), "sspm::google_workspace::drive-link-sharing-default", types.SeverityMedium,
			"New Drive files default to link-sharing", target+"/drive",
			"New files default to 'anyone with the link' sharing — data is exposed by default rather than by deliberate choice. Set the default access to 'Private to the owner'.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-1"}})))
	}
	if t.LessSecureAppsEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::less-secure-apps-enabled", types.SeverityHigh,
			"'Less secure app' access is enabled", target,
			"Less-secure-app access permits basic-auth sign-in that bypasses 2-step verification — a password-spray / account-takeover vector. Disable less-secure-app access org-wide.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AC-7"}, NIST80053: []string{"IA-2"}})))
	}
	if t.ThirdPartyAPIAccess {
		f = append(f, finding(id(), "sspm::google_workspace::third-party-app-access-unrestricted", types.SeverityMedium,
			"Third-party app API access is unrestricted", target,
			"Any third-party OAuth app can be granted access to Drive/Gmail data with no app allowlist or API-access controls — a shadow-IT + data-exfil risk. Restrict API access to vetted, allowlisted apps.",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.AC-5"}})))
	}
	if t.GmailExternalAutoForward {
		f = append(f, finding(id(), "sspm::google_workspace::gmail-external-autoforward", types.SeverityMedium,
			"Users may auto-forward mail to external addresses", target+"/gmail",
			"Automatic forwarding to external addresses is allowed — a common data-exfiltration + BEC-persistence technique. Disable external auto-forwarding (allow only admin-approved exceptions).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, HIPAA: []string{"164.312(e)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if n := formsGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::forms-external-exchange", types.SeverityMedium,
			"Forms exchange data externally ("+strings.Join(n, ", ")+")", target+"/drive",
			"Forms move data across the organisation boundary: "+strings.Join(n, ", ")+
				". A form looks like a document rather than a channel, so it routinely sits outside whatever "+
				"sharing policy the estate has — responses arrive from outside and submissions leave, without "+
				"either passing the controls applied to files. Restrict external form responses and "+
				"submissions (SCuBA GWS.DRIVEDOCS.1.10v1 / 1.11v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.SharedDriveCreationOverridable {
		f = append(f, finding(id(), "sspm::google_workspace::shared-drive-creation-overridable", types.SeverityLow,
			"Managers may override shared-drive creation settings", target+"/drive",
			"Members with manager access on any shared drive can override the organisation's creation "+
				"settings, which makes the org-level policy a default rather than a control — it applies "+
				"exactly until someone with manager rights decides otherwise, and nothing records that they "+
				"did. Prevent managers from overriding creation settings (SCuBA GWS.DRIVEDOCS.2.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}})))
	}
	if t.NonMembersCannotBeAddedToFiles {
		f = append(f, finding(id(), "sspm::google_workspace::non-members-cannot-be-added-to-files", types.SeverityLow,
			"Non-members cannot be added to files in shared drives", target+"/drive",
			"Adding a non-member to an individual file is blocked. That sounds stricter and is not: the "+
				"sharing still has to happen, so people copy the file OUT of the shared drive to send it — and "+
				"the copy leaves behind the drive's access controls, its audit trail and its retention in a "+
				"single step. Allow non-members to be added to files so sharing stays inside the drive where "+
				"it can be governed (SCuBA GWS.DRIVEDOCS.2.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.PostSSOVerificationOff || t.PostSSOVerificationOffOther {
		f = append(f, finding(id(), "sspm::google_workspace::post-sso-verification-off", types.SeverityMedium,
			"No additional verification is performed after SSO", target,
			"Google performs no further check once an SSO assertion is accepted, so anyone who can produce "+
				"one is in — including an attacker who has compromised the identity provider rather than any "+
				"individual account. SSO concentrates the tenant's trust in a single external system, and "+
				"post-SSO verification is the only control that does not depend on that system being intact. "+
				"Enable post-SSO verification (SCuBA GWS.COMMONCONTROLS.3.1v1 / 3.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2"}})))
	}
	if n := unassessedServiceGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::unassessed-services-enabled", types.SeverityMedium,
			"Services nobody assessed are enabled ("+strings.Join(n, ", ")+")", target,
			"These are on: "+strings.Join(n, ", ")+
				". The default for a Google service with no individual admin control is ON, which means every "+
				"service Google ships is enabled on the day it ships, without anyone deciding — the estate "+
				"grows a new surface each time the vendor releases something. Set unassessed services to OFF "+
				"for everyone and enable them deliberately (SCuBA GWS.COMMONCONTROLS.16.1v1–16.4v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"2.3", "3.3"}, NISTCSF: []string{"PR.IP-1"}, NIST80053: []string{"CM-7"}})))
	}
	if t.RecoveryInfoAllowed {
		f = append(f, finding(id(), "sspm::google_workspace::recovery-info-allowed", types.SeverityMedium,
			"Users may add their own account-recovery information", target,
			"Users can register a personal phone or email for self-service recovery, which makes those the "+
				"real credential: whoever controls a ported number or a personal mailbox can reset the account "+
				"without the password or the second factor. Disable user-added recovery information and route "+
				"resets through an administrator (SCuBA GWS.COMMONCONTROLS.8.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.3"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.AccountConflictUnmanaged {
		f = append(f, finding(id(), "sspm::google_workspace::account-conflict-unmanaged", types.SeverityMedium,
			"Conflicting unmanaged accounts are not being absorbed", target,
			"Personal Google accounts created on the corporate domain remain UNMANAGED rather than being "+
				"replaced with managed ones. They hold company data, appear in no admin console, cannot be "+
				"suspended, and survive offboarding completely — an ex-employee keeps them along with whatever "+
				"is in them. Configure account conflict management to replace them "+
				"(SCuBA GWS.COMMONCONTROLS.7.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"5.1", "6.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"AC-2"}})))
	}
	if t.PasswordMinLength >= 12 && t.PasswordMinLength < 16 {
		f = append(f, finding(id(), "sspm::google_workspace::password-min-length-below-recommended", types.SeverityLow,
			fmt.Sprintf("Minimum password length is %d, below the recommended 16", t.PasswordMinLength), target,
			"The minimum meets the 12-character floor but not the 16-character recommendation. "+
				"The gap matters most for the accounts that never get a second factor — service and shared "+
				"accounts — where length is the only thing standing between a credential dump and a working "+
				"password. Raise the minimum to 16 (SCuBA GWS.COMMONCONTROLS.5.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.PhishingResistant2SVNotEnforced {
		f = append(f, finding(id(), "sspm::google_workspace::phishing-resistant-2sv-not-enforced", types.SeverityHigh,
			"Phishing-resistant 2-step verification is not enforced", target,
			"2SV is required but any method satisfies it, including a code the user types. That is exactly "+
				"what an adversary-in-the-middle proxy relays: the user completes a genuine challenge on a "+
				"convincing page and the attacker keeps the session. Only a security key is bound to the origin "+
				"and cannot be replayed. Enforce security keys (SCuBA GWS.COMMONCONTROLS.1.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.3", "6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2"}})))
	}
	if t.UnconfiguredThirdPartyAppsAllowed {
		f = append(f, finding(id(), "sspm::google_workspace::unconfigured-third-party-apps-allowed", types.SeverityMedium,
			"Users may access unconfigured third-party applications", target,
			"Applications nobody has reviewed — from outside the domain entirely — can be granted access by "+
				"users. Unlike an internal app there is no colleague to ask about it and no registration to "+
				"look up; the only thing standing between the app and the data is a consent screen read in a "+
				"hurry. Require configuration before third-party app access "+
				"(SCuBA GWS.COMMONCONTROLS.10.4v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-6"}})))
	}
	if t.DriveSDKEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::drive-sdk-enabled", types.SeverityMedium,
			"Drive SDK access is enabled", target+"/drive",
			"Third-party applications can read and write Drive through the API. This reaches the FILES "+
				"directly rather than the account, so an app with a stale or over-broad grant is a standing "+
				"channel to every document a user can see — and API access leaves no trace a user would "+
				"recognise as unusual. Disable Drive SDK access if it is not required "+
				"(SCuBA GWS.DRIVEDOCS.4.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3", "CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.POPIMAPEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::pop-imap-enabled", types.SeverityHigh,
			"POP and IMAP access is enabled", target+"/gmail",
			"POP and IMAP authenticate with a password alone and will stream an entire mailbox. After an "+
				"account compromise this is how the mail actually leaves — it is the exfiltration step rather "+
				"than the entry, and it looks like a mail client rather than an attack. Disable POP and IMAP "+
				"(SCuBA GWS.GMAIL.9.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, GDPR: []string{"Art. 32"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2", "AC-3"}})))
	}
	if t.SecondaryCalendarExternalSharing {
		f = append(f, finding(id(), "sspm::google_workspace::secondary-calendar-external-sharing", types.SeverityMedium,
			"Secondary calendars are shared externally", target+"/calendar",
			"Secondary calendars share separately from the primary one, and they are where project, "+
				"on-call and interview schedules usually live — so the calendar most worth reading is precisely "+
				"the one the primary setting does not cover. Restrict external sharing for secondary calendars "+
				"(SCuBA GWS.CALENDAR.1.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.CalendarInteropBasicAuth {
		f = append(f, finding(id(), "sspm::google_workspace::calendar-interop-basic-auth", types.SeverityMedium,
			"Calendar Interop authenticates with basic auth rather than the Graph API", target+"/calendar",
			"Free/busy sharing with an external Exchange organisation is authenticated by a standing "+
				"credential rather than the Graph API. Basic auth is replayable, unprotected by MFA, and the "+
				"credential lives in another organisation's mail system where your controls do not reach. Use "+
				"the Graph API for Calendar Interop (SCuBA GWS.CALENDAR.3.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2", "IA-5"}})))
	}
	// NOT an else-branch. 3.1 and 3.2 are different requirements with different fixes:
	// "disable Interop" and "if you use Interop, do not authenticate it with basic auth".
	// A tenant using Interop over the Graph API violates the first and satisfies the
	// second, so collapsing them would silently drop a finding for exactly the tenant that
	// did the harder half of the work.
	if t.CalendarInteropEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::calendar-interop-enabled", types.SeverityLow,
			"Calendar Interop is enabled", target+"/calendar",
			"Free/busy data is shared with an external Exchange organisation. Availability patterns reveal "+
				"more than they appear to — who meets whom, how often, and when something unusual is "+
				"happening — which is useful reconnaissance for social engineering. Disable Interop if it is "+
				"not needed (SCuBA GWS.CALENDAR.3.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.AppointmentPaymentsEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::appointment-payments-enabled", types.SeverityLow,
			"Appointment scheduling with payments is enabled", target+"/calendar",
			"Calendar can take payments, which places a payment flow — and the PCI scope that follows it — "+
				"inside a feature nobody assessed as a payment system. The exposure is less the flow itself "+
				"than that it sits outside whatever review payment handling normally gets. Disable "+
				"appointment payments unless deliberately in scope (SCuBA GWS.CALENDAR.4.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, PCI: []string{"12.5.1"}, CISv8: []string{"3.3"}})))
	}
	if n := spoofGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::spoofing-protection-disabled", types.SeverityHigh,
			"Gmail spoofing protection is off ("+strings.Join(n, ", ")+")", target+"/gmail",
			"Inbound mail is not being checked for impersonation: "+strings.Join(n, ", ")+
				". Employee-name spoofing is the one to look at first — business-email compromise usually needs "+
				"no domain trick at all, just a display name your staff recognise on a message asking for a "+
				"payment or a password. Enable Gmail's spoofing and authentication protections "+
				"(SCuBA GWS.GMAIL.7.1v1 / 7.2v1 / 7.5v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3", "SI-8"}})))
	}
	if n := autoApplyGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::security-auto-apply-off", types.SeverityMedium,
			"Gmail does not auto-apply future recommended protections ("+strings.Join(n, ", ")+")", target+"/gmail",
			"New protections Google ships will not be applied: "+strings.Join(n, ", ")+
				". This is the setting that decides whether posture DECAYS — with it off, the tenant's defences "+
				"stay frozen at whatever was configured the day someone last looked, while the attacks they "+
				"were built against keep moving. Allow automatic application of recommended settings "+
				"(SCuBA GWS.GMAIL.6.4v1 / 7.7v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.1"}, CISv8: []string{"9.6"}, NISTCSF: []string{"PR.IP-1"}, NIST80053: []string{"SI-2"}})))
	}
	if t.PreDeliveryScanningOff {
		f = append(f, finding(id(), "sspm::google_workspace::pre-delivery-scanning-off", types.SeverityHigh,
			"Enhanced pre-delivery message scanning is disabled", target+"/gmail",
			"Suspicious mail is assessed only after it is already in the mailbox. Pre-delivery scanning is "+
				"the difference between a message the user never sees and one they have to decide about — and "+
				"the decision is made in the two seconds before a morning meeting. Enable enhanced "+
				"pre-delivery scanning (SCuBA GWS.GMAIL.15.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3"}})))
	}
	if t.ExternalOutboundGateway {
		f = append(f, finding(id(), "sspm::google_workspace::external-outbound-gateway", types.SeverityHigh,
			"Outbound mail may be routed through a non-Google server", target+"/gmail",
			"A per-user outbound gateway sends mail through a server Google does not operate. Whoever runs "+
				"that server reads everything the organisation sends and can alter it in transit, and none of "+
				"it appears in Workspace's own logs — the interception is indistinguishable from normal "+
				"delivery from inside the tenant. Disable per-user outbound gateways "+
				"(SCuBA GWS.GMAIL.12.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6", "CC6.7"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.10"}, NISTCSF: []string{"PR.DS-2"}, NIST80053: []string{"SC-8"}})))
	}
	if t.UserEmailUploadsEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::user-email-uploads-enabled", types.SeverityMedium,
			"Users may upload external mail into Workspace", target+"/gmail",
			"Mail can be imported from outside the tenant, bringing attachments and links that never passed "+
				"the inbound filters — the protections are applied at the front door and this is a side "+
				"entrance. Disable user email uploads (SCuBA GWS.GMAIL.8.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3"}})))
	}
	if t.SpamBypassAllSenders {
		f = append(f, finding(id(), "sspm::google_workspace::spam-bypass-all-senders", types.SeverityHigh,
			"Spam filtering is bypassed and warnings hidden for all senders", target+"/gmail",
			"The org-wide bypass is on: spam filtering is skipped and warning banners suppressed for every "+
				"sender, internal and external. This is worse than a per-domain allowlist because it removes "+
				"the warning a user would otherwise still see — the filter and the last line of defence go "+
				"together. Disable the bypass (SCuBA GWS.GMAIL.18.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3", "SI-8"}})))
	}
	if t.MailDelegationEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::mail-delegation-enabled", types.SeverityMedium,
			"Mail delegation is enabled", target+"/gmail",
			"Users may grant others full access to their mailbox. Delegation is granted for a reason that "+
				"expires — cover during leave, an assistant who changed role — and is almost never reviewed "+
				"afterwards, so it accumulates as standing access to the most sensitive store in the company. "+
				"Disable mail delegation, or review existing grants (SCuBA GWS.GMAIL.1.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-6"}})))
	}
	if t.DeviceTrustAllowed {
		f = append(f, finding(id(), "sspm::google_workspace::device-trust-allowed", types.SeverityHigh,
			"Users may mark devices trusted and skip 2-step verification", target,
			"A user can mark a device trusted, after which sign-ins from it skip 2SV. That is an MFA bypass "+
				"the user grants themselves, it applies to whoever is holding the device, and it survives the "+
				"password reset performed after a compromise — the second factor is gone precisely when it is "+
				"most needed. Disable device trust (SCuBA GWS.COMMONCONTROLS.1.5v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2"}})))
	}
	if t.SessionNeverExpires {
		f = append(f, finding(id(), "sspm::google_workspace::session-never-expires", types.SeverityMedium,
			"Sessions never require re-authentication", target,
			"There is no forced re-authentication, so a session cookie lifted from a browser — by malware, a "+
				"shared machine, or an infostealer — works indefinitely and needs no password and no second "+
				"factor. Session length is what separates an incident from a persistent foothold. Set a "+
				"re-authentication period (SCuBA GWS.COMMONCONTROLS.4.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"AC-12"}})))
	}
	if t.TwoSVEnrollmentPeriodDays > 7 {
		f = append(f, finding(id(), "sspm::google_workspace::twosv-enrollment-grace-too-long", types.SeverityMedium,
			fmt.Sprintf("New users have %d days before 2-step verification is required", t.TwoSVEnrollmentPeriodDays), target,
			fmt.Sprintf("A new account may sign in for %d days with a single factor. Freshly-provisioned "+
				"accounts are the ones whose credentials are most often mishandled — mailed, messaged, read "+
				"aloud — so the grace window lands exactly where the risk is highest. Set the enrolment period "+
				"to at most one week (SCuBA GWS.COMMONCONTROLS.1.4v1).", t.TwoSVEnrollmentPeriodDays),
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, NIST80053: []string{"IA-2"}})))
	}
	if t.TakeoutEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::takeout-enabled", types.SeverityHigh,
			"Google Takeout is enabled for users", target,
			"Any user can export their entire Workspace footprint — mail, Drive, calendar — as a downloadable "+
				"archive. It is a one-click bulk-exfiltration channel that raises no alert and is "+
				"indistinguishable from a legitimate action, which is exactly why a compromised account and a "+
				"departing employee both reach for it. Disable Takeout (SCuBA GWS.COMMONCONTROLS.12.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}, NIST80053: []string{"AC-3"}})))
	}
	if t.UserConsentLowRiskScopes {
		f = append(f, finding(id(), "sspm::google_workspace::user-consent-low-risk-scopes", types.SeverityMedium,
			"Users may grant third-party apps access without review", target,
			"Users can consent to apps requesting low-risk scopes with no administrator review. Low-risk is "+
				"Google's judgement about the SCOPE, not about the application holding it or who controls that "+
				"application next month, and the grant is standing. Require admin review for third-party app "+
				"access (SCuBA GWS.COMMONCONTROLS.10.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-6"}})))
	}
	if t.UnconfiguredInternalAppsTrusted {
		f = append(f, finding(id(), "sspm::google_workspace::unconfigured-internal-apps-trusted", types.SeverityMedium,
			"Unconfigured internal applications are trusted by default", target,
			"Applications registered inside the domain are trusted without being configured. \"Internal\" "+
				"describes who registered the app, not who controls it now — an abandoned project, a departed "+
				"developer's OAuth client, or a compromised internal service inherits that trust. Require "+
				"internal apps to be configured before they are trusted (SCuBA GWS.COMMONCONTROLS.10.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-6"}})))
	}
	if t.AdminAccountsNotCloudOnly {
		f = append(f, finding(id(), "sspm::google_workspace::admin-accounts-not-cloud-only", types.SeverityMedium,
			"Administrative accounts are federated rather than cloud-only", target,
			"Admin accounts authenticate through an external identity source, so a compromise of THAT "+
				"directory is a compromise of Workspace administration. The tenant inherits the weakest link of "+
				"a system its own controls do not reach, and the usual break-glass assumption — that cloud "+
				"admin survives an on-premises incident — does not hold. Provision admin accounts cloud-only "+
				"(SCuBA GWS.COMMONCONTROLS.6.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.3"}, CISv8: []string{"5.4"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-2", "AC-6"}})))
	}
	if n := driveWarningGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::drive-external-share-warnings-disabled", types.SeverityMedium,
			"Drive external-sharing warnings are off ("+strings.Join(n, ", ")+")", target+"/drive",
			"Users are not warned before a file leaves the organisation: "+strings.Join(n, ", ")+
				". The warning is the last moment a mis-shared document is still cheap to undo — after it, the "+
				"file is out and the only remedy is revocation nobody thinks to perform. Enable Drive sharing "+
				"warnings (SCuBA GWS.DRIVEDOCS.1.3v1 / 1.9v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.DriveSecurityUpdateNotApplied {
		f = append(f, finding(id(), "sspm::google_workspace::drive-security-update-not-applied", types.SeverityHigh,
			"The Google Drive link-security update has not been applied", target+"/drive",
			"Sharing links created before Google's Drive security update lack the resource key that makes a "+
				"link unguessable, so any such link that leaked or was enumerated STILL WORKS today. This is "+
				"the rare setting that is retroactive: applying it invalidates existing exposure rather than "+
				"only preventing new. Apply the security update to Drive files (SCuBA GWS.DRIVEDOCS.3.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}, NIST80053: []string{"AC-3"}})))
	}
	if t.DriveRansomwareMonitoringDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::drive-ransomware-monitoring-disabled", types.SeverityMedium,
			"Drive ransomware-corruption monitoring is disabled", target+"/drive",
			"Drive is not watching for the mass-corruption signature of ransomware encrypting a synced "+
				"folder. Without it the first sign is a user noticing their files are unreadable — by which "+
				"point sync has already propagated the encryption to everyone sharing the drive. Enable "+
				"ransomware-corruption monitoring (SCuBA GWS.DRIVEDOCS.5.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, CISv8: []string{"10.1", "11.1"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3", "SI-4"}})))
	}
	if t.DriveNonGoogleAccountSharing {
		f = append(f, finding(id(), "sspm::google_workspace::drive-non-google-account-sharing", types.SeverityMedium,
			"Files can be shared with recipients who have no Google account", target+"/drive",
			"Sharing to non-Google recipients works via a link plus an emailed PIN, so the person opening the "+
				"file is unauthenticated in any sense the audit log can record — access is proof of holding an "+
				"email, and forwarding that email transfers it. Restrict external sharing to Google accounts "+
				"(SCuBA GWS.DRIVEDOCS.1.4v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.DriveExternalSharedDriveUpload {
		f = append(f, finding(id(), "sspm::google_workspace::drive-external-shared-drive-upload", types.SeverityMedium,
			"Users may move content into shared drives owned by other organisations", target+"/drive",
			"Content can be uploaded or moved into a shared drive another organisation owns. That is an "+
				"exfiltration path shaped exactly like ordinary collaboration, and once moved the file sits "+
				"under someone else's retention, access control and deletion policy. Block uploads to "+
				"externally-owned shared drives (SCuBA GWS.DRIVEDOCS.1.7v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if n := attachmentGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::attachment-protection-disabled", types.SeverityHigh,
			"Gmail advanced attachment protection is off ("+strings.Join(n, ", ")+")", target+"/gmail",
			"Attachments from untrusted senders are not being inspected for "+strings.Join(n, ", ")+
				". These arrive as ordinary mail with no added scrutiny, and each is a standard malware "+
				"delivery route — an encrypted archive defeats content scanning by design, a script-bearing "+
				"attachment executes on open, and an anomalous type is how a payload is disguised as a "+
				"document. Enable Gmail's advanced attachment protections (SCuBA GWS.GMAIL.5.1v1–5.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6", "10.1"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3", "SI-8"}})))
	}
	if n := linkGapsOf(t); len(n) > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::link-protection-disabled", types.SeverityHigh,
			"Gmail advanced link protection is off ("+strings.Join(n, ", ")+")", target+"/gmail",
			"Links in inbound mail are not being inspected: "+strings.Join(n, ", ")+
				". A URL shortener is the cheapest way to put a known-bad destination past a filter that only "+
				"reads the visible text, and without a click-time warning the first thing that tells the user "+
				"anything is the credential-harvesting page itself. Enable Gmail's advanced link and image "+
				"protections (SCuBA GWS.GMAIL.6.1v1–6.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3", "SI-8"}})))
	}
	if t.SuspiciousMailKeptInInbox {
		f = append(f, finding(id(), "sspm::google_workspace::suspicious-mail-kept-in-inbox", types.SeverityHigh,
			"Mail flagged as malicious is delivered to the inbox", target+"/gmail",
			"Messages Gmail's own protections identify as spoofing, phishing or carrying a dangerous "+
				"attachment are still delivered rather than quarantined. This setting decides whether the "+
				"others do anything: a detection that lands in front of the user is a warning label on a weapon "+
				"they are already holding. Route flagged mail to quarantine "+
				"(SCuBA GWS.GMAIL.5.4v1 / 7.6v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"9.6"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3", "SI-8"}})))
	}
	if t.ExternalInviteWarningsDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::external-invite-warnings-disabled", types.SeverityLow,
			"No warning before inviting external guests to a calendar event", target+"/calendar",
			"Users are not prompted when an invitee is outside the organisation, so a mistyped or look-alike "+
				"domain receives the meeting link, the subject and the full attendee list with nothing asking "+
				"the sender to look twice. Enable external-invitation warnings (SCuBA GWS.CALENDAR.2.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.ExternalCalendarSharing {
		f = append(f, finding(id(), "sspm::google_workspace::external-calendar-sharing", types.SeverityLow,
			"Calendar details are shared externally", target+"/calendar",
			"Calendars publish full event details externally — leaking meeting subjects, attendees, and availability (useful for social-engineering). Limit external calendar sharing to free/busy only.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, NISTCSF: []string{"PR.DS-1"}})))
	}

	// --- Checks closing mandatory CISA SCuBA gaps (see the struct comment). Each
	// fires only on an explicitly-supplied signal.

	if t.WeakMFAMethodsEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::weak-mfa-methods-enabled", types.SeverityHigh,
			"Phishable 2SV methods (SMS / voice) are enabled", target,
			"SMS and voice-call are permitted as 2-Step Verification methods. Both are phishable in real time and SMS is SIM-swappable, so 2SV is present but bypassable. Restrict 2SV to security keys or Google Prompt (SCuBA GWS.COMMONCONTROLS.1.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"6.3", "6.5"}, NISTCSF: []string{"PR.AC-7"}, NIST80053: []string{"IA-2"}})))
	}
	if t.SuperAdminSelfRecoveryEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::super-admin-self-recovery-enabled", types.SeverityHigh,
			"Super-admin account self-recovery is enabled", target,
			"Super admins can recover their own accounts, so an attacker who controls a recovery channel (a ported phone number, a personal mailbox) can reset a super-admin password without touching the current credential or its 2SV. Disable self-recovery for super admins and recover via another admin (SCuBA GWS.COMMONCONTROLS.8.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.5"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"5.4", "6.3"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.UserSelfRecoveryEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::user-self-recovery-enabled", types.SeverityMedium,
			"Account self-recovery is enabled for users", target,
			"Non-super-admin users can self-recover, making a compromised recovery channel a route back into the account. Disable self-recovery and route resets through an administrator (SCuBA GWS.COMMONCONTROLS.8.2v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.3"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.PasswordMinLength > 0 && t.PasswordMinLength < 12 {
		f = append(f, finding(id(), "sspm::google_workspace::password-min-length-too-short", types.SeverityMedium,
			fmt.Sprintf("Minimum password length is %d characters", t.PasswordMinLength),
			target,
			fmt.Sprintf("The enforced minimum password length is %d, below the 12-character baseline, leaving accounts materially easier to brute-force or crack from a credential dump. Raise the minimum to at least 12 (SCuBA GWS.COMMONCONTROLS.5.2v1).", t.PasswordMinLength),
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.6"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.PasswordStrengthNotEnforced {
		f = append(f, finding(id(), "sspm::google_workspace::password-strength-not-enforced", types.SeverityMedium,
			"Password strength enforcement is disabled", target,
			"The password-strength requirement is off, so users may set trivially guessable passwords. Enable strength enforcement (SCuBA GWS.COMMONCONTROLS.5.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.6"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.PasswordPolicyNotEnforcedAtSignIn {
		f = append(f, finding(id(), "sspm::google_workspace::password-policy-not-enforced-at-signin", types.SeverityMedium,
			"Password policy is not enforced at next sign-in", target,
			"A strengthened password policy applies only to passwords set AFTER the change, so every account "+
				"that does not voluntarily rotate keeps its old one indefinitely — raising the minimum length "+
				"changes nothing for the accounts most likely to have a weak password. Enforce the policy at "+
				"next sign-in (SCuBA GWS.COMMONCONTROLS.5.4v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.6"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.PasswordReuseAllowed {
		f = append(f, finding(id(), "sspm::google_workspace::password-reuse-allowed", types.SeverityMedium,
			"Password reuse is permitted", target,
			"Users may set a password they have used before. Any credential of theirs already sitting in a "+
				"breach dump becomes valid again the moment they rotate back to it, which is the one outcome a "+
				"rotation is supposed to prevent. Block reuse (SCuBA GWS.COMMONCONTROLS.5.5v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.7"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.PasswordExpiryDays > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::password-expiry-enabled", types.SeverityLow,
			fmt.Sprintf("Passwords are forced to expire every %d days", t.PasswordExpiryDays), target,
			fmt.Sprintf("Passwords expire every %d days. Forced rotation is now advised AGAINST by both CISA and "+
				"NIST SP 800-63B: it drives users to predictable increments and to writing passwords down, which "+
				"costs more than the compromise window it shortens. Set expiry to never and rely on strength, "+
				"reuse-blocking and MFA (SCuBA GWS.COMMONCONTROLS.5.6v1).", t.PasswordExpiryDays),
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"5.2"}, NISTCSF: []string{"PR.AC-1"}, NIST80053: []string{"IA-5"}})))
	}
	if t.SpamBypassDomains > 0 {
		f = append(f, finding(id(), "sspm::google_workspace::spam-filter-bypass-list", types.SeverityMedium,
			fmt.Sprintf("%d domain(s) bypass the spam filter", t.SpamBypassDomains), target+"/gmail",
			fmt.Sprintf("%d domain(s) are allowlisted past spam filtering, so anything sent from (or spoofing) them reaches the inbox unscanned — and allowlists are rarely revisited after the vendor issue that prompted them. Remove the bypass entries (SCuBA GWS.GMAIL.18.1v1).", t.SpamBypassDomains),
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.5", "9.7"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-8"}})))
	}
	if t.DriveAccessCheckingLoose {
		f = append(f, finding(id(), "sspm::google_workspace::drive-access-checking-loose", types.SeverityMedium,
			"Drive link access-checking is wider than recipients-only", target+"/drive",
			"Share links are not restricted to their intended recipients, so a forwarded link keeps working for whoever holds it. Set access checking to 'recipients only' (SCuBA GWS.DRIVEDOCS.1.6v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if t.ExternalReplyWarningsDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::external-reply-warnings-disabled", types.SeverityLow,
			"Unintended external reply warnings are disabled", target+"/gmail",
			"Users get no warning when replying to someone outside the organisation, so a thread hijacked by a lookalike address draws no attention. Enable unintended-external-reply warnings (SCuBA GWS.GMAIL.13.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"9.5"}, NISTCSF: []string{"PR.AT-1"}, NIST80053: []string{"SI-8"}})))
	}
	if t.InboundSpoofProtectionDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::inbound-spoof-protection-disabled", types.SeverityHigh,
			"Protection against inbound mail spoofing your own domain is disabled", target+"/gmail",
			"Gmail is not acting on inbound mail that claims to come from the organisation's own domain — the highest-trust BEC vector, since the message appears to be from a colleague. Enable protection against inbound emails spoofing your domain (SCuBA GWS.GMAIL.7.3v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-8"}})))
	}
	if t.UnauthenticatedEmailProtectionDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::unauthenticated-email-protection-disabled", types.SeverityMedium,
			"Protection against unauthenticated email is disabled", target+"/gmail",
			"Mail that fails SPF/DKIM/DMARC authentication outright is still delivered normally, undermining the domain-authentication posture the org publishes. Enable protection against any unauthenticated emails (SCuBA GWS.GMAIL.7.4v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-8"}})))
	}
	if t.WorkspaceSyncEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::workspace-sync-enabled", types.SeverityMedium,
			"Google Workspace Sync for Microsoft Outlook is enabled", target+"/gmail",
			"GWSMO keeps a full local replica of mail, calendar and contacts inside an Outlook profile on "+
				"the endpoint. That copy sits outside every Workspace-side control: DLP does not inspect it, "+
				"suspending the account does not reach it, and an offboarding checklist that revokes access "+
				"leaves the mailbox on the laptop. Disable Google Workspace Sync "+
				"(SCuBA GWS.GMAIL.10.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.7"}, HIPAA: []string{"164.312(a)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}, NIST80053: []string{"AC-19"}})))
	}
	if t.EmailAllowlistImplemented {
		f = append(f, finding(id(), "sspm::google_workspace::email-allowlist-implemented", types.SeverityMedium,
			"An email allowlist is configured", target+"/gmail",
			"Gmail's email allowlist does not grant access — it EXEMPTS the listed senders from spam and "+
				"phishing filtering, so their mail arrives unexamined. The addresses that end up on it are "+
				"the trusted partners and vendors an attacker most wants to impersonate, which makes the "+
				"list a description of exactly whom to spoof. Remove the allowlist and fix the false "+
				"positives it was papering over (SCuBA GWS.GMAIL.14.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.7"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-8"}})))
	}
	if t.SecuritySandboxDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::security-sandbox-disabled", types.SeverityMedium,
			"Gmail security sandbox is disabled", target+"/gmail",
			"Attachments are not detonated in a sandbox before delivery, so each one is judged on "+
				"signatures and sender reputation alone. That catches payloads someone has already seen and "+
				"reported; it does not catch the one built for this target, which is the only kind a "+
				"targeted campaign sends. Enable the security sandbox "+
				"(SCuBA GWS.GMAIL.16.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6", "CC7.1"}, PCI: []string{"5.2.1"}, CISv8: []string{"9.6", "10.1"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3"}})))
	}
	if t.ComprehensiveMailStorageDisabled {
		f = append(f, finding(id(), "sspm::google_workspace::comprehensive-mail-storage-disabled", types.SeverityLow,
			"Comprehensive mail storage is disabled", target+"/gmail",
			"Mail generated by non-Gmail Workspace applications is not stored in the associated user's "+
				"mailbox, so it never reaches Vault, eDiscovery, retention or a mailbox export. Nothing "+
				"reports the gap: it becomes visible only when an investigation or a legal hold asks for a "+
				"message and finds it was never kept. Enable comprehensive mail storage "+
				"(SCuBA GWS.GMAIL.17.1v1).",
			now, comp(types.Compliance{SOC2: []string{"CC7.2"}, HIPAA: []string{"164.312(b)"}, CISv8: []string{"8.2"}, NISTCSF: []string{"DE.CM-1"}, NIST80053: []string{"AU-11"}, SOX: []string{"ITGC-Logging"}})))
	}
	return f
}

// attachmentGapsOf names which attachment protections are off, so the finding says WHICH
// rather than only that something is. Three settings, one control: an attacker needs
// whichever one is disabled, so any of them is the finding.
func attachmentGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.EncryptedAttachmentProtectionDisabled {
		n = append(n, "encrypted attachments")
	}
	if t.ScriptAttachmentProtectionDisabled {
		n = append(n, "attachments with scripts")
	}
	if t.AnomalousAttachmentProtectionDisabled {
		n = append(n, "anomalous attachment types")
	}
	return n
}

// linkGapsOf is the link-side twin.
func linkGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.ShortenedURLScanDisabled {
		n = append(n, "shortened URLs are not expanded")
	}
	if t.LinkedImageScanDisabled {
		n = append(n, "linked images are not scanned")
	}
	if t.UntrustedLinkWarningsOff {
		n = append(n, "no warning on links to untrusted domains")
	}
	return n
}

// driveWarningGapsOf names which Drive sharing warnings are off. Two settings, one
// control, and the finding says which — the same shape as the Gmail attachment cluster.
func driveWarningGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.DriveExternalShareWarningsDisabled {
		n = append(n, "no warning when sharing to a non-allowlisted domain")
	}
	if t.DriveOutOfDomainWarningsDisabled {
		n = append(n, "no out-of-domain file-level warning")
	}
	return n
}

// spoofGapsOf names which spoofing protections are off.
func spoofGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.SimilarDomainSpoofProtectionOff {
		n = append(n, "look-alike domains not detected")
	}
	if t.EmployeeNameSpoofProtectionOff {
		n = append(n, "employee-name impersonation not detected")
	}
	if t.GroupsSpoofProtectionOff {
		n = append(n, "Groups not protected from mail spoofing your own domain")
	}
	return n
}

// autoApplyGapsOf names which auto-apply settings are off — the posture-decay control.
func autoApplyGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.LinkAutoApplyOff {
		n = append(n, "links and external images")
	}
	if t.SpoofAutoApplyOff {
		n = append(n, "spoofing and authentication")
	}
	return n
}

// unassessedServiceGapsOf names which unassessed-by-default services are enabled.
func unassessedServiceGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.UnassessedServicesEnabled {
		n = append(n, "services with no individual control")
	}
	if t.EarlyAccessAppsEnabled {
		n = append(n, "Early Access applications")
	}
	if t.LookerStudioExternalShare {
		n = append(n, "Looker Studio sharing outside the org")
	}
	if t.PinpointDriveAccess {
		n = append(n, "Pinpoint access to Drive")
	}
	return n
}

// formsGapsOf names which Forms external-exchange paths are open.
func formsGapsOf(t GWorkspaceTenant) []string {
	var n []string
	if t.FormsAcceptExternalResponses {
		n = append(n, "forms accept responses from outside the organisation")
	}
	if t.FormsSubmitExternally {
		n = append(n, "users may submit to forms owned outside the organisation")
	}
	return n
}
