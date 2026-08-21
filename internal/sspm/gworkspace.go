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
	InboundSpoofProtectionDisabled         bool `json:"inbound_spoof_protection_disabled,omitempty"`
	UnauthenticatedEmailProtectionDisabled bool `json:"unauthenticated_email_protection_disabled,omitempty"`
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
	return f
}
