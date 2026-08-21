package bench

// SCuBA — the NEUTRAL benchmark for the AI Identity/SaaS Engineer specialist.
//
// The specialist taxonomy (CLAUDE.md §2.2.1) listed identity/SaaS posture as
// having "no neutral bench". That was wrong: CISA's **Secure Cloud Business
// Applications (SCuBA)** project publishes machine-checkable secure-configuration
// baselines for Microsoft 365 (assessed by cisagov/ScubaGear) and Google Workspace
// (cisagov/ScubaGoggles) — a government-published, vendor-neutral, CC0 control set
// that is exactly the surface `internal/operate` (identity) + `internal/sspm`
// (SaaS config) assess. It is the identity/SaaS analogue of what IAM-Vulnerable is
// for the cloud specialist: third-party ground truth we did not author.
//
// This file is the TRANSCRIBED CATALOG (policy id · product · requirement ·
// SHALL/SHOULD · scope) plus the mapping to the tsengine rule ids that detect each
// violation. It is deliberately DATA ONLY — the number is produced by
// scuba_test.go, which for every mapped policy builds a violating snapshot, runs
// the REAL assessor, and asserts the mapped rule actually fires. An unproven
// mapping fails the test rather than inflating coverage (§10: the claim is only as
// good as the executed evidence).
//
// Honesty about the denominator (the same discipline as grc.Coverage's
// "no false compliant"): a baseline written for federal civilian agencies contains
// requirements that are not config-detectable posture for a commercial tenant, so
// each policy carries a Scope and the report states BOTH raw and in-scope coverage.
// Nothing here claims SCuBA compliance — it measures detection recall against an
// authoritative external control set.
//
// Source: https://github.com/cisagov/ScubaGear (M365) ·
// https://github.com/cisagov/ScubaGoggles (Google Workspace). Public domain (CC0).
// Requirement text is terse paraphrase for identification only.

// SCuBAScope records whether a baseline policy is something a posture SCANNER can
// decide from an admin-API snapshot at all.
type SCuBAScope string

const (
	// ScopeDetectable — a configuration fact visible in an admin-API snapshot.
	// These form the honest denominator for a detection-recall claim.
	ScopeDetectable SCuBAScope = "detectable"
	// ScopeProcedural — requires org process or an operator-supplied approved-list
	// / retention / SIEM-routing decision, not a config bit we can read and judge.
	ScopeProcedural SCuBAScope = "procedural"
	// ScopeFederal — FCEB-specific (the reports@dmarc.cyber.dhs.gov contact, US
	// data region). Not applicable to a commercial tenant; excluded from in-scope.
	ScopeFederal SCuBAScope = "federal"
)

// SCuBAPolicy is one baseline policy and the tsengine rules that detect its
// violation. A rule prefixed "~" is PARTIAL: we detect an adjacent or weaker
// condition (e.g. "admin has no MFA" vs the baseline's "admin MFA must be
// phishing-resistant"), counted separately so partial never reads as full.
type SCuBAPolicy struct {
	ID          string
	Product     string
	Requirement string
	Shall       bool // SHALL (mandatory) vs SHOULD (recommended)
	Scope       SCuBAScope
	Rules       []string
}

// Partial reports whether the policy is only partially covered.
func (p SCuBAPolicy) Partial() bool {
	if len(p.Rules) == 0 {
		return false
	}
	for _, r := range p.Rules {
		if len(r) > 0 && r[0] != '~' {
			return false
		}
	}
	return true
}

// Covered reports whether any tsengine rule is mapped (full or partial).
func (p SCuBAPolicy) Covered() bool { return len(p.Rules) > 0 }

// SCuBACatalog returns the transcribed CISA SCuBA baseline policy set.
func SCuBACatalog() []SCuBAPolicy {
	return []SCuBAPolicy{
		{ID: "MS.AAD.1.1v1", Product: "m365/entra", Requirement: "Legacy authentication SHALL be blocked.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::legacy-auth-enabled"}},
		{ID: "MS.AAD.2.1v1", Product: "m365/entra", Requirement: "Users detected as high risk SHALL be blocked.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::risky-users-not-blocked"}},
		{ID: "MS.AAD.2.2v1", Product: "m365/entra", Requirement: "A notification SHOULD be sent to the administrator when high-risk users are detected.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.2.3v1", Product: "m365/entra", Requirement: "Sign-ins detected as high risk SHALL be blocked.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::risky-signins-not-blocked"}},
		{ID: "MS.AAD.3.1v1", Product: "m365/entra", Requirement: "Phishing-resistant MFA SHALL be enforced for all users.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~sspm::m365::weak-mfa-methods-enabled"}},
		{ID: "MS.AAD.3.2v2", Product: "m365/entra", Requirement: "MFA SHALL be enforced for all users.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::user-without-mfa"}},
		{ID: "MS.AAD.3.3v2", Product: "m365/entra", Requirement: "If Microsoft Authenticator is enabled, it SHALL be configured to show login context information.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.3.4v1", Product: "m365/entra", Requirement: "The Authentication Methods Manage Migration feature SHALL be set to Migration Complete.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.3.5v2", Product: "m365/entra", Requirement: "The authentication methods SMS, Voice Call, and Email One-Time Passcode (OTP) SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::weak-mfa-methods-enabled"}},
		{ID: "MS.AAD.3.6v1", Product: "m365/entra", Requirement: "Phishing-resistant MFA SHALL be required for highly privileged roles.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~operate::admin-without-mfa"}},
		{ID: "MS.AAD.3.7v1", Product: "m365/entra", Requirement: "Managed devices SHOULD be required for authentication.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.3.8v1", Product: "m365/entra", Requirement: "Managed Devices SHOULD be required to register MFA.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.3.9v1", Product: "m365/entra", Requirement: "Device code authentication SHOULD be blocked.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.4.1v1", Product: "m365/entra", Requirement: "Security logs SHALL be sent to the agency's security operations center for monitoring.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.5.1v1", Product: "m365/entra", Requirement: "Only administrators SHALL be allowed to register applications.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::user-app-registration-allowed"}},
		{ID: "MS.AAD.5.2v1", Product: "m365/entra", Requirement: "User consent to applications SHALL be restricted.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~operate::oauth-admin-scope"}},
		{ID: "MS.AAD.5.3v1", Product: "m365/entra", Requirement: "An admin consent workflow SHALL be configured for applications.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::admin-consent-workflow-disabled"}},
		{ID: "MS.AAD.5.5v1", Product: "m365/entra", Requirement: "Application Password Addition SHOULD be blocked.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.5.6v1", Product: "m365/entra", Requirement: "Application password lifetime SHOULD be restricted to 180 days or less.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.5.7v1", Product: "m365/entra", Requirement: "Application certificate lifetime SHOULD be restricted to 365 days or less.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.6.1v1", Product: "m365/entra", Requirement: "User passwords SHALL NOT expire.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::password-expiry-enabled"}},
		{ID: "MS.AAD.7.1v1", Product: "m365/entra", Requirement: "A minimum of two users and a maximum of eight users SHALL be provisioned with the Global Administrator role.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::excess-super-admins"}},
		{ID: "MS.AAD.7.2v1", Product: "m365/entra", Requirement: "Privileged users SHALL be provisioned with finer-grained roles instead of Global Administrator.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::standing-global-admin"}},
		{ID: "MS.AAD.7.3v1", Product: "m365/entra", Requirement: "Privileged users SHALL be provisioned cloud-only accounts separate from an on-premises directory or other federated identity providers.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.7.4v1", Product: "m365/entra", Requirement: "Permanent active role assignments SHALL NOT be allowed for highly privileged roles.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::permanent-privileged-roles"}},
		{ID: "MS.AAD.7.5v1", Product: "m365/entra", Requirement: "Provisioning users to highly privileged roles SHALL NOT occur outside of a PAM system.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "MS.AAD.7.6v1", Product: "m365/entra", Requirement: "Activation of the Global Administrator role SHALL require approval.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "MS.AAD.7.7v1", Product: "m365/entra", Requirement: "Eligible and active highly privileged role assignments SHALL trigger an alert.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.7.8v1", Product: "m365/entra", Requirement: "User activation of the Global Administrator role SHALL trigger an alert.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::global-admin-activation-no-alert"}},
		{ID: "MS.AAD.7.9v1", Product: "m365/entra", Requirement: "User activation of other highly privileged roles SHOULD trigger an alert.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.8.1v1", Product: "m365/entra", Requirement: "Guest users SHOULD have limited or restricted access to Microsoft Entra ID directory objects.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.8.2v1", Product: "m365/entra", Requirement: "Only users with the Guest Inviter role SHOULD be able to invite guest users.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.8.3v1", Product: "m365/entra", Requirement: "Guest invites SHOULD only be allowed to specific external domains that have been authorized by the agency for legitimate business purposes.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.AAD.9.1v1", Product: "m365/entra", Requirement: "Risky AI agents SHALL be blocked.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.EXO.1.1v2", Product: "m365/exchange", Requirement: "Automatic forwarding to external domains SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::external-autoforward-allowed"}},
		{ID: "MS.EXO.2.2v3", Product: "m365/exchange", Requirement: "An SPF policy SHALL be published for each domain that fails all non-approved senders.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::spf-dkim-missing", "operate::spf-permissive-all"}},
		{ID: "MS.EXO.3.1v1", Product: "m365/exchange", Requirement: "DKIM SHOULD be enabled for all domains.", Shall: false, Scope: ScopeDetectable, Rules: []string{"operate::spf-dkim-missing"}},
		{ID: "MS.EXO.4.1v1", Product: "m365/exchange", Requirement: "A DMARC policy SHALL be published for every second-level domain.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::dmarc-not-enforced"}},
		{ID: "MS.EXO.4.2v1", Product: "m365/exchange", Requirement: "The DMARC message rejection option SHALL be p=reject.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::dmarc-not-rejecting", "operate::dmarc-partial-enforcement"}},
		{ID: "MS.EXO.4.3v1", Product: "m365/exchange", Requirement: "The DMARC point of contact for aggregate reports SHALL include reports@dmarc.cyber.dhs.gov.", Shall: true, Scope: ScopeFederal, Rules: nil},
		{ID: "MS.EXO.4.4v1", Product: "m365/exchange", Requirement: "An agency point of contact SHOULD be included for aggregate and failure reports.", Shall: false, Scope: ScopeFederal, Rules: nil},
		{ID: "MS.EXO.5.1v1", Product: "m365/exchange", Requirement: "SMTP AUTH SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~sspm::m365::legacy-auth-enabled"}},
		{ID: "MS.EXO.6.1v1", Product: "m365/exchange", Requirement: "Contact folders SHALL NOT be shared with all domains.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.EXO.6.2v1", Product: "m365/exchange", Requirement: "Calendar details SHALL NOT be shared with all domains.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::anonymous-calendar-sharing"}},
		{ID: "MS.EXO.7.1v1", Product: "m365/exchange", Requirement: "External sender warnings SHALL be implemented.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::external-sender-warnings-disabled"}},
		{ID: "MS.EXO.13.1v1", Product: "m365/exchange", Requirement: "Mailbox auditing SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::mailbox-auditing-disabled"}},
		{ID: "MS.SHAREPOINT.1.1v1", Product: "m365/sharepoint", Requirement: "External sharing for SharePoint SHALL be limited to \"Existing guests\" or \"Only people in your organization\".", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::sharepoint-anonymous-sharing"}},
		{ID: "MS.SHAREPOINT.1.2v1", Product: "m365/sharepoint", Requirement: "External sharing for OneDrive SHALL be limited to \"Existing guests\" or \"Only people in your organization\".", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::onedrive-anonymous-sharing"}},
		{ID: "MS.SHAREPOINT.1.3v1", Product: "m365/sharepoint", Requirement: "External sharing SHALL be restricted to approved external domains and/or users in approved security groups per interagency collaboration needs.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::external-sharing-no-allowlist"}},
		{ID: "MS.SHAREPOINT.2.1v1", Product: "m365/sharepoint", Requirement: "File and folder default sharing scope SHALL be set to \"Specific people (only the people the user specifies)\".", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::default-sharing-scope-anyone"}},
		{ID: "MS.SHAREPOINT.2.2v1", Product: "m365/sharepoint", Requirement: "File and folder default sharing permissions SHALL be set to view only.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::default-link-permission-edit"}},
		{ID: "MS.SHAREPOINT.3.1v1", Product: "m365/sharepoint", Requirement: "Expiration days for Anyone links SHALL be set to 30 days or less.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::anyone-link-expiry-too-long"}},
		{ID: "MS.SHAREPOINT.3.2v1", Product: "m365/sharepoint", Requirement: "The allowable file and folder permissions for links SHALL be set to view only.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.SHAREPOINT.3.3v2", Product: "m365/sharepoint", Requirement: "Reauthentication days for people who use a verification code SHALL be set to 30 days or less.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.TEAMS.1.1v1", Product: "m365/teams", Requirement: "External meeting participants SHOULD NOT be enabled to request control of shared desktops or windows.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::m365::teams-external-control-request"}},
		{ID: "MS.TEAMS.1.2v2", Product: "m365/teams", Requirement: "Anonymous users SHALL NOT be enabled to start meetings.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::teams-anonymous-start-meeting"}},
		{ID: "MS.TEAMS.1.3v1", Product: "m365/teams", Requirement: "Anonymous users and dial-in callers SHOULD NOT be admitted automatically.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::m365::teams-auto-admit-anonymous"}},
		{ID: "MS.TEAMS.1.4v1", Product: "m365/teams", Requirement: "Internal users SHOULD be admitted automatically.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.TEAMS.1.5v1", Product: "m365/teams", Requirement: "Dial-in users SHOULD NOT be enabled to bypass the lobby.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::m365::teams-dial-in-bypass-lobby"}},
		{ID: "MS.TEAMS.1.6v1", Product: "m365/teams", Requirement: "Meeting recording SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.TEAMS.1.7v2", Product: "m365/teams", Requirement: "Record an event SHOULD NOT be set to Always record.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.TEAMS.2.1v2", Product: "m365/teams", Requirement: "External access for users SHALL only be enabled on a per-domain basis.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::teams-open-federation"}},
		{ID: "MS.TEAMS.2.2v2", Product: "m365/teams", Requirement: "Unmanaged users SHALL NOT be enabled to initiate contact with internal users.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~sspm::m365::teams-guest-unrestricted"}},
		{ID: "MS.TEAMS.2.3v2", Product: "m365/teams", Requirement: "Internal users SHOULD NOT be enabled to initiate contact with unmanaged users.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "MS.TEAMS.4.1v1", Product: "m365/teams", Requirement: "Teams email integration SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::m365::teams-email-integration-enabled"}},
		{ID: "MS.TEAMS.5.1v2", Product: "m365/teams", Requirement: "Agencies SHOULD only allow installation of Microsoft apps approved by the agency.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "MS.TEAMS.5.2v2", Product: "m365/teams", Requirement: "Agencies SHOULD only allow installation of third-party apps approved by the agency.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "MS.TEAMS.5.3v2", Product: "m365/teams", Requirement: "Agencies SHOULD only allow installation of custom apps approved by the agency.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.1.1v1", Product: "gws/common", Requirement: "Phishing-Resistant MFA SHALL be required for all users.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~operate::user-without-mfa"}},
		{ID: "GWS.COMMONCONTROLS.1.2v1", Product: "gws/common", Requirement: "If phishing-resistant MFA has not been enforced, an alternative MFA method SHALL be enforced for all users.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::user-without-mfa"}},
		{ID: "GWS.COMMONCONTROLS.1.3v1", Product: "gws/common", Requirement: "SMS or Voice SHALL NOT be used as the MFA method.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::weak-mfa-methods-enabled"}},
		{ID: "GWS.COMMONCONTROLS.1.4v1", Product: "gws/common", Requirement: "The Google 2-Step Verification (2SV) new user enrollment period SHALL be set to at least one day and at most one week.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::twosv-enrollment-grace-too-long"}},
		{ID: "GWS.COMMONCONTROLS.1.5v1", Product: "gws/common", Requirement: "Allow users to trust the device SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::device-trust-allowed"}},
		{ID: "GWS.COMMONCONTROLS.2.1v1", Product: "gws/common", Requirement: "Policies restricting access to Google Workspace (GWS) based on enterprise device signals SHOULD be implemented.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.3.1v1", Product: "gws/common", Requirement: "Post-single sign-on (SSO) verification SHOULD be enabled for users signing in using the organization's SSO profile.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.3.2v1", Product: "gws/common", Requirement: "Post-SSO verification SHOULD be enabled for users signing in using other SSO profiles.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.4.1v1", Product: "gws/common", Requirement: "Users SHALL be forced to re-authenticate after an established 12-hour GWS login session has expired.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::session-never-expires"}},
		{ID: "GWS.COMMONCONTROLS.5.1v1", Product: "gws/common", Requirement: "User password strength SHALL be enforced.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::password-strength-not-enforced"}},
		{ID: "GWS.COMMONCONTROLS.5.2v1", Product: "gws/common", Requirement: "User password length SHALL be at least 12 characters.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::password-min-length-too-short"}},
		{ID: "GWS.COMMONCONTROLS.5.3v1", Product: "gws/common", Requirement: "User password length SHOULD be at least 16 characters.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.5.4v1", Product: "gws/common", Requirement: "Password policy SHALL be enforced at next sign-in.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::password-policy-not-enforced-at-signin"}},
		{ID: "GWS.COMMONCONTROLS.5.5v1", Product: "gws/common", Requirement: "User passwords SHALL NOT be reused.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::password-reuse-allowed"}},
		{ID: "GWS.COMMONCONTROLS.5.6v1", Product: "gws/common", Requirement: "User passwords SHALL NOT expire.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::password-expiry-enabled"}},
		{ID: "GWS.COMMONCONTROLS.6.1v1", Product: "gws/common", Requirement: "All administrative accounts SHALL be provisioned as cloud-only accounts separate from an agency's authoritative on-premises or other federated iden...", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::admin-accounts-not-cloud-only"}},
		{ID: "GWS.COMMONCONTROLS.6.2v1", Product: "gws/common", Requirement: "A minimum of two and a maximum of eight separate and distinct super admin users SHALL be configured.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::excess-super-admins"}},
		{ID: "GWS.COMMONCONTROLS.7.1v1", Product: "gws/common", Requirement: "Account conflict management SHOULD be configured to replace conflicting unmanaged accounts with managed accounts.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.8.1v1", Product: "gws/common", Requirement: "Account self-recovery for super admins SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::super-admin-self-recovery-enabled"}},
		{ID: "GWS.COMMONCONTROLS.8.2v1", Product: "gws/common", Requirement: "Account self-recovery for users and non-super admins SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::user-self-recovery-enabled"}},
		{ID: "GWS.COMMONCONTROLS.8.3v1", Product: "gws/common", Requirement: "Ability to add recovery information SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.9.1v1", Product: "gws/common", Requirement: "Highly privileged accounts SHALL be enrolled in the Google Workspace (GWS) Advanced Protection Program.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.9.2v1", Product: "gws/common", Requirement: "All sensitive user accounts SHOULD be enrolled into the GWS Advanced Protection Program.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.10.1v1", Product: "gws/common", Requirement: "Agencies SHALL use GWS application access control policies to restrict access to all GWS services by third-party applications.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::third-party-app-access-unrestricted"}},
		{ID: "GWS.COMMONCONTROLS.10.2v1", Product: "gws/common", Requirement: "Agencies SHALL NOT allow users to grant consent for access to low-risk scopes.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::user-consent-low-risk-scopes"}},
		{ID: "GWS.COMMONCONTROLS.10.3v1", Product: "gws/common", Requirement: "Agencies SHALL NOT trust unconfigured internal applications.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::unconfigured-internal-apps-trusted"}},
		{ID: "GWS.COMMONCONTROLS.10.4v1", Product: "gws/common", Requirement: "Agencies SHALL NOT allow users to access unconfigured third-party applications.", Shall: true, Scope: ScopeDetectable, Rules: []string{"~operate::oauth-unverified-app"}},
		{ID: "GWS.COMMONCONTROLS.10.5v1", Product: "gws/common", Requirement: "Access to GWS applications by less secure applications that do not meet security authentication standards SHALL be prevented.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::less-secure-apps-enabled"}},
		{ID: "GWS.COMMONCONTROLS.11.1v1", Product: "gws/common", Requirement: "Only approved Google Workspace (GWS) Marketplace applications SHALL be allowed for installation.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.12.1v1", Product: "gws/common", Requirement: "Google Takeout services SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::takeout-enabled"}},
		{ID: "GWS.COMMONCONTROLS.13.1v1", Product: "gws/common", Requirement: "Required system-defined alerting rules, as listed in the policy group description, SHALL be enabled with alerts.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.14.1v1", Product: "gws/common", Requirement: "The following critical logs SHALL be sent to the agency's centralized SIEM.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.14.2v1", Product: "gws/common", Requirement: "Audit logs SHALL be retained and searchable for a minimum of 3 months and retrievable for a minimum of 12 months.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.15.1v1", Product: "gws/common", Requirement: "The data storage region SHALL be set to be the United States for all users in the agency's GWS environment.", Shall: true, Scope: ScopeFederal, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.15.2v1", Product: "gws/common", Requirement: "Data SHALL be processed in the region selected for data at rest.", Shall: true, Scope: ScopeFederal, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.16.1v1", Product: "gws/common", Requirement: "Service status for Google services that do not have an individual control SHOULD be set to OFF for everyone.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.16.2v1", Product: "gws/common", Requirement: "User access to Early Access applications SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.16.3v1", Product: "gws/common", Requirement: "Looker Studio Sharing outside org SHOULD be set to OFF.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.16.4v1", Product: "gws/common", Requirement: "Pinpoint access to drive SHOULD be set to OFF.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.17.1v1", Product: "gws/common", Requirement: "Require multi-party approval for sensitive admin actions SHOULD be enabled.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.18.1v1", Product: "gws/common", Requirement: "A custom policy SHALL be configured for Google Drive, Google Calendar, Google Chat, and Gmail to protect PII and sensitive information as defined b...", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.COMMONCONTROLS.18.2v1", Product: "gws/common", Requirement: "The action for DLP policies SHOULD be set to block.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.DRIVEDOCS.1.1v1", Product: "gws/drive", Requirement: "External sharing SHALL be restricted to allowlisted domains.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-external-no-allowlist"}},
		{ID: "GWS.DRIVEDOCS.1.2v1", Product: "gws/drive", Requirement: "Receiving files from non-allowlisted domains SHOULD be disabled.", Shall: false, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.DRIVEDOCS.1.3v1", Product: "gws/drive", Requirement: "Warnings SHALL be enabled when a user is attempting to share with someone in a non-allowlisted domain.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-external-share-warnings-disabled"}},
		{ID: "GWS.DRIVEDOCS.1.4v1", Product: "gws/drive", Requirement: "If sharing outside of the organization, agencies SHOULD disable sharing of files with individuals who are not using a Google account.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-non-google-account-sharing"}},
		{ID: "GWS.DRIVEDOCS.1.5v1", Product: "gws/drive", Requirement: "Any Organizational Units that allow external sharing SHOULD disable content availability to \"anyone with the link.\"", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-public-sharing"}},
		{ID: "GWS.DRIVEDOCS.1.6v1", Product: "gws/drive", Requirement: "Agencies SHALL set access checking to \"recipients only.\"", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-access-checking-loose"}},
		{ID: "GWS.DRIVEDOCS.1.7v1", Product: "gws/drive", Requirement: "Users SHOULD NOT be allowed to upload or move content to shared drives owned by another organization.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-external-shared-drive-upload"}},
		{ID: "GWS.DRIVEDOCS.1.8v1", Product: "gws/drive", Requirement: "\"Private to owner\" SHALL be the default access level for newly created items.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-link-sharing-default"}},
		{ID: "GWS.DRIVEDOCS.1.9v1", Product: "gws/drive", Requirement: "Out-of-Domain file-level warnings SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-external-share-warnings-disabled"}},
		{ID: "GWS.DRIVEDOCS.1.10v1", Product: "gws/drive", Requirement: "If external sharing is not allowed, then forms owned by users within the organization SHOULD NOT be able to accept responses from anyone accessing...", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.DRIVEDOCS.1.11v1", Product: "gws/drive", Requirement: "If receiving external files is not allowed, then users in the organization SHOULD NOT be able to submit responses to forms from users or shared dri...", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.DRIVEDOCS.2.1v1", Product: "gws/drive", Requirement: "Agencies SHOULD NOT allow members with manager access to override shared Google Drive creation settings.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.DRIVEDOCS.2.2v1", Product: "gws/drive", Requirement: "Agencies SHALL allow users who are not members of a shared Google Drive to be added to files.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.DRIVEDOCS.3.1v1", Product: "gws/drive", Requirement: "Agencies SHALL enable the security update for Google Drive files.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-security-update-not-applied"}},
		{ID: "GWS.DRIVEDOCS.4.1v1", Product: "gws/drive", Requirement: "Agencies SHOULD disable Google Drive SDK access.", Shall: false, Scope: ScopeDetectable, Rules: []string{"~sspm::google_workspace::third-party-app-access-unrestricted"}},
		{ID: "GWS.DRIVEDOCS.5.1v1", Product: "gws/drive", Requirement: "Google Drive for Desktop SHALL be enabled for authorized devices only.", Shall: true, Scope: ScopeProcedural, Rules: nil},
		{ID: "GWS.DRIVEDOCS.5.2v1", Product: "gws/drive", Requirement: "Monitoring for potential ransomware corruption SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::drive-ransomware-monitoring-disabled"}},
		{ID: "GWS.GMAIL.1.1v1", Product: "gws/gmail", Requirement: "Mail delegation SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.2.1v1", Product: "gws/gmail", Requirement: "DKIM SHOULD be enabled for all domains.", Shall: false, Scope: ScopeDetectable, Rules: []string{"operate::spf-dkim-missing"}},
		{ID: "GWS.GMAIL.3.1v1", Product: "gws/gmail", Requirement: "An SPF policy SHALL be published for each domain that fails all non-approved senders.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::spf-dkim-missing", "operate::spf-permissive-all"}},
		{ID: "GWS.GMAIL.4.1v1", Product: "gws/gmail", Requirement: "A DMARC policy SHALL be published at the full domain or the second-level domain for all Google Workspace domains, including user alias domains.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::dmarc-not-enforced"}},
		{ID: "GWS.GMAIL.4.2v1", Product: "gws/gmail", Requirement: "The DMARC message rejection option SHALL be p=reject.", Shall: true, Scope: ScopeDetectable, Rules: []string{"operate::dmarc-not-rejecting", "operate::dmarc-partial-enforcement"}},
		{ID: "GWS.GMAIL.4.3v1", Product: "gws/gmail", Requirement: "The DMARC point of contact for aggregate reports SHALL include reports@dmarc.cyber.dhs.gov.", Shall: true, Scope: ScopeFederal, Rules: nil},
		{ID: "GWS.GMAIL.4.4v1", Product: "gws/gmail", Requirement: "An agency point of contact SHOULD be included for aggregate and failure reports.", Shall: false, Scope: ScopeFederal, Rules: nil},
		{ID: "GWS.GMAIL.5.1v1", Product: "gws/gmail", Requirement: "\"Protect against encrypted attachments from untrusted senders\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::attachment-protection-disabled"}},
		{ID: "GWS.GMAIL.5.2v1", Product: "gws/gmail", Requirement: "\"Protect against attachments with scripts from untrusted senders\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::attachment-protection-disabled"}},
		{ID: "GWS.GMAIL.5.3v1", Product: "gws/gmail", Requirement: "\"Protect against anomalous attachment types in emails\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::attachment-protection-disabled"}},
		{ID: "GWS.GMAIL.5.4v1", Product: "gws/gmail", Requirement: "Google SHOULD be allowed to automatically apply future recommended settings for attachments.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::suspicious-mail-kept-in-inbox"}},
		{ID: "GWS.GMAIL.5.5v1", Product: "gws/gmail", Requirement: "Emails flagged by SCuBA policies GWS.GMAIL.5.1 through GWS.GMAIL.5.3 SHALL NOT be kept in inbox.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.6.1v1", Product: "gws/gmail", Requirement: "\"Identify links behind shortened URLs\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::link-protection-disabled"}},
		{ID: "GWS.GMAIL.6.2v1", Product: "gws/gmail", Requirement: "\"Scan linked images\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::link-protection-disabled"}},
		{ID: "GWS.GMAIL.6.3v1", Product: "gws/gmail", Requirement: "\"Show warning prompt for any click on links to untrusted domains\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::link-protection-disabled"}},
		{ID: "GWS.GMAIL.6.4v1", Product: "gws/gmail", Requirement: "Google SHALL be allowed to automatically apply future recommended settings for links and external images.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.7.1v1", Product: "gws/gmail", Requirement: "\"Protect against domain spoofing based on similar domain names\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.7.2v1", Product: "gws/gmail", Requirement: "\"Protect against spoofing of employee names\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.7.3v1", Product: "gws/gmail", Requirement: "\"Protect against inbound emails spoofing your domain\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::inbound-spoof-protection-disabled"}},
		{ID: "GWS.GMAIL.7.4v1", Product: "gws/gmail", Requirement: "\"Protect against any unauthenticated emails\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::unauthenticated-email-protection-disabled"}},
		{ID: "GWS.GMAIL.7.5v1", Product: "gws/gmail", Requirement: "\"Protect your Groups from inbound emails spoofing your domain\" SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.7.6v1", Product: "gws/gmail", Requirement: "Emails flagged by SCuBA policies GWS.GMAIL.7.1 through GWS.GMAIL.7.5 SHALL NOT be kept in inbox.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::suspicious-mail-kept-in-inbox"}},
		{ID: "GWS.GMAIL.7.7v1", Product: "gws/gmail", Requirement: "Google SHALL be allowed to automatically apply future recommended settings for spoofing and authentication.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.8.1v1", Product: "gws/gmail", Requirement: "User email uploads SHALL be disabled to protect against unauthorized files being introduced into the secured environment.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.9.1v1", Product: "gws/gmail", Requirement: "POP and IMAP access SHALL be disabled to protect sensitive agency or organization emails from being accessed through legacy applications or other t...", Shall: true, Scope: ScopeDetectable, Rules: []string{"~sspm::google_workspace::less-secure-apps-enabled"}},
		{ID: "GWS.GMAIL.10.1v1", Product: "gws/gmail", Requirement: "Google Workspace Sync SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.11.1v1", Product: "gws/gmail", Requirement: "Automatic forwarding SHOULD be disabled, especially to external domains.", Shall: false, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::gmail-external-autoforward"}},
		{ID: "GWS.GMAIL.12.1v1", Product: "gws/gmail", Requirement: "The option to use a per-user outbound gateway that is a mail server other than the Google Workspace (GWS) mail servers SHALL be disabled.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.13.1v1", Product: "gws/gmail", Requirement: "Unintended external reply warnings SHALL be enabled.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::external-reply-warnings-disabled"}},
		{ID: "GWS.GMAIL.14.1v1", Product: "gws/gmail", Requirement: "An email allowlist SHOULD NOT be implemented.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.15.1v1", Product: "gws/gmail", Requirement: "Enhanced pre-delivery message scanning SHALL be enabled to prevent phishing.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.16.1v1", Product: "gws/gmail", Requirement: "Security sandbox SHOULD be enabled to provide additional email protections.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.17.1v1", Product: "gws/gmail", Requirement: "Comprehensive mail storage SHOULD be enabled to allow information traceability across applications.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.18.1v1", Product: "gws/gmail", Requirement: "Domains SHALL NOT be added to lists that bypass spam filters.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::spam-filter-bypass-list"}},
		{ID: "GWS.GMAIL.18.2v1", Product: "gws/gmail", Requirement: "Domains SHALL NOT be added to lists that bypass spam filters and hide warnings.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.GMAIL.18.3v1", Product: "gws/gmail", Requirement: "\"Bypass spam filters\" and \"hide warnings for all messages from internal and external senders\" SHALL NOT be enabled.", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.CALENDAR.1.1v1", Product: "gws/calendar", Requirement: "External sharing options for primary calendars SHALL be configured to \"Only free/busy information (hide event details).\"", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::external-calendar-sharing"}},
		{ID: "GWS.CALENDAR.1.2v1", Product: "gws/calendar", Requirement: "External sharing options for secondary calendars SHALL be configured to \"Only free/busy information (hide event details).\"", Shall: true, Scope: ScopeDetectable, Rules: []string{"~sspm::google_workspace::external-calendar-sharing"}},
		{ID: "GWS.CALENDAR.2.1v1", Product: "gws/calendar", Requirement: "External invitations warnings SHALL be enabled to prompt users before sending invitations.", Shall: true, Scope: ScopeDetectable, Rules: []string{"sspm::google_workspace::external-invite-warnings-disabled"}},
		{ID: "GWS.CALENDAR.3.1v1", Product: "gws/calendar", Requirement: "Calendar Interop SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.CALENDAR.3.2v1", Product: "gws/calendar", Requirement: "Microsoft 365 (Graph API) SHALL be used instead of basic authentication to establish connectivity between tenants or organizations in cases where C...", Shall: true, Scope: ScopeDetectable, Rules: nil},
		{ID: "GWS.CALENDAR.4.1v1", Product: "gws/calendar", Requirement: "\"Appointment Schedule with Payments\" SHOULD be disabled.", Shall: false, Scope: ScopeDetectable, Rules: nil},
	}
}
