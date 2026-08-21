package bench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/sspm"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The SCuBA benchmark's integrity rests on one property: a mapping in
// scuba.go must be EXECUTED, not asserted. These tests run the real
// `operate` + `sspm` assessors over deliberately-misconfigured tenants and
// require that every rule id the catalog claims is genuinely emitted. A typo,
// a renamed rule, or a mapping to a check that does not exist fails the build
// instead of quietly inflating the recall number.

// worstCaseRules runs every assessor over a maximally-misconfigured estate and
// returns the set of rule ids actually emitted.
func worstCaseRules(t *testing.T) map[string]bool {
	t.Helper()
	emitted := map[string]bool{}
	add := func(f []types.Finding) {
		for _, x := range f {
			emitted[x.RuleID] = true
		}
	}

	// --- M365 collaboration/data-sharing posture (sspm) ---
	add(sspm.AssessM365(sspm.M365Tenant{
		Name:                    "contoso",
		SharePointSharing:       "anonymous",
		OneDriveSharing:         "anonymous",
		ExternalDomainAllowlist: false,
		TeamsGuestAccess:        true,
		TeamsGuestUnrestricted:  true,
		TeamsOpenFederation:     true,
		LegacyAuthEnabled:       true,
		MailboxAuditingEnabled:  sspm.BoolPtr(false),
		AnonymousCalendarShare:  true,
		// the mandatory-gap fields (bypassable auth, standing privilege, exfil paths)
		ExternalAutoForwardEnabled:     true,
		WeakMFAMethodsEnabled:          true,
		RiskyUserBlockDisabled:         true,
		RiskySignInBlockDisabled:       true,
		UserAppRegistrationAllowed:     true,
		PermanentPrivilegedAssignments: true,
		ExternalSenderWarningsDisabled: true,
		AnyoneLinksNeverExpire:         true,
		DefaultSharingScope:            "anyone",
		DefaultLinkPermission:          "edit",
		TeamsAutoAdmitAnonymous:        true,
		TeamsDialInBypassLobby:         true,
		TeamsExternalControlRequest:    true,
		TeamsEmailIntegrationEnabled:   true,
		TeamsAnonymousStartMeeting:     true,
	}, sspm.Options{}))
	// The expiry rule must also fire on a supplied-but-too-long window, not only on
	// the explicit never-expires flag.
	add(sspm.AssessM365(sspm.M365Tenant{Name: "contoso-expiry", AnyoneLinkExpiryDays: 90}, sspm.Options{}))
	// A second pass with "external" (not anonymous) sharing so the
	// no-allowlist rule, which only applies at the external level, fires.
	add(sspm.AssessM365(sspm.M365Tenant{
		Name: "contoso-ext", SharePointSharing: "external", OneDriveSharing: "external",
		ExternalDomainAllowlist: false,
	}, sspm.Options{}))

	// --- Google Workspace collaboration posture (sspm) ---
	add(sspm.AssessGoogleWorkspace(sspm.GWorkspaceTenant{
		Name: "acme", DriveSharing: "public", DriveLinkSharingDefault: true,
		LessSecureAppsEnabled: true, ThirdPartyAPIAccess: true,
		GmailExternalAutoForward: true, ExternalCalendarSharing: true,
		ExternalInviteWarningsDisabled:        true,
		EncryptedAttachmentProtectionDisabled: true,
		ScriptAttachmentProtectionDisabled:    true,
		AnomalousAttachmentProtectionDisabled: true,
		ShortenedURLScanDisabled:              true,
		LinkedImageScanDisabled:               true,
		UntrustedLinkWarningsOff:              true,
		SuspiciousMailKeptInInbox:             true,
		// the mandatory-gap fields (mirrors the M365 set)
		WeakMFAMethodsEnabled:                  true,
		SuperAdminSelfRecoveryEnabled:          true,
		UserSelfRecoveryEnabled:                true,
		PasswordMinLength:                      8,
		PasswordStrengthNotEnforced:            true,
		PasswordPolicyNotEnforcedAtSignIn:      true,
		PasswordReuseAllowed:                   true,
		PasswordExpiryDays:                     90,
		SpamBypassDomains:                      2,
		DriveAccessCheckingLoose:               true,
		ExternalReplyWarningsDisabled:          true,
		InboundSpoofProtectionDisabled:         true,
		UnauthenticatedEmailProtectionDisabled: true,
	}, sspm.Options{}))
	add(sspm.AssessGoogleWorkspace(sspm.GWorkspaceTenant{
		Name: "acme-ext", DriveSharing: "external", DriveExternalAllowlist: false,
	}, sspm.Options{}))

	// --- Identity + email-auth posture (operate), both providers ---
	for _, provider := range []string{"m365", "gworkspace"} {
		add(operate.Assess(operate.Workspace{
			Provider: provider, Org: "acme",
			Users: []operate.User{
				{Email: "ga1@acme.test", Admin: true, SuperAdmin: true, MFA: false},
				{Email: "ga2@acme.test", Admin: true, SuperAdmin: true, MFA: true},
				{Email: "ga3@acme.test", Admin: true, SuperAdmin: true, MFA: true},
				{Email: "ga4@acme.test", Admin: true, SuperAdmin: true, MFA: true},
				{Email: "ga5@acme.test", Admin: true, SuperAdmin: true, MFA: true},
				{Email: "user1@acme.test", MFA: false},
				{Email: "stale@acme.test", MFA: true, LastLoginDays: 400},
				{Email: "gone@acme.test", Admin: true, SuperAdmin: true, MFA: true, Suspended: true},
			},
			Domains: []operate.DomainConfig{
				// no DMARC at all + no SPF/DKIM
				{Name: "acme.test", DMARC: "none", SPF: false, DKIM: false},
				// enforcing but only quarantining, plus a permissive SPF all-qualifier
				{Name: "mail.acme.test", DMARC: "quarantine", SPF: true, DKIM: true, SPFAll: "+"},
				// rejecting, but rolled out to only a fraction of mail (pct<100)
				{Name: "rollout.acme.test", DMARC: "reject", SPF: true, DKIM: true, SPFAll: "-", DMARCPct: 25},
			},
			OAuthGrants: []operate.OAuthGrant{
				{App: "shadow-admin", Scopes: []string{"https://www.googleapis.com/auth/admin.directory.user"}, Users: 3, AdminScope: true, Verified: true},
				{App: "random-tool", Scopes: []string{"https://www.googleapis.com/auth/drive"}, Users: 12, Verified: false},
			},
		}, operate.Options{}))
	}
	return emitted
}

// Every rule id the SCuBA mapping claims must be really emitted by a real
// assessor. This is what stops the coverage number from being self-graded.
func TestSCuBAMappedRulesAreRealAndReachable(t *testing.T) {
	emitted := worstCaseRules(t)
	score := ScoreSCuBA(SCuBACatalog())
	if len(score.Rules) == 0 {
		t.Fatal("catalog maps no tsengine rules — the benchmark would be vacuous")
	}
	var missing []string
	for _, r := range score.Rules {
		if !emitted[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		t.Errorf("SCuBA mapping claims %d rule(s) no assessor emits (unproven coverage): %v",
			len(missing), missing)
		t.Logf("assessors emitted %d distinct rules", len(emitted))
	} else {
		t.Logf("[PASS] all %d mapped rules proven live by the real assessors", len(score.Rules))
	}
}

// FP control: a hardened estate must yield ZERO findings. Recall without
// specificity is worthless — the same pairing every asset bench uses (§14.1.1).
func TestSCuBAHardenedEstateIsClean(t *testing.T) {
	if f := sspm.AssessM365(sspm.M365Tenant{
		Name: "hardened", SharePointSharing: "internal", OneDriveSharing: "internal",
		ExternalDomainAllowlist: true, MailboxAuditingEnabled: sspm.BoolPtr(true),
	}, sspm.Options{}); len(f) != 0 {
		t.Errorf("hardened M365 tenant produced %d finding(s), want 0: %s", len(f), ruleList(f))
	}
	if f := sspm.AssessGoogleWorkspace(sspm.GWorkspaceTenant{
		Name: "hardened", DriveSharing: "restricted", DriveExternalAllowlist: true,
	}, sspm.Options{}); len(f) != 0 {
		t.Errorf("hardened Google Workspace tenant produced %d finding(s), want 0: %s", len(f), ruleList(f))
	}
	if f := operate.Assess(operate.Workspace{
		Provider: "m365", Org: "hardened",
		Users: []operate.User{
			{Email: "a@h.test", Admin: true, SuperAdmin: true, MFA: true},
			{Email: "b@h.test", Admin: true, SuperAdmin: true, MFA: true},
			{Email: "c@h.test", MFA: true},
		},
		Domains: []operate.DomainConfig{{Name: "h.test", DMARC: "reject", SPF: true, DKIM: true, SPFAll: "-", DMARCPct: 100}},
	}, operate.Options{}); len(f) != 0 {
		t.Errorf("hardened identity posture produced %d finding(s), want 0: %s", len(f), ruleList(f))
	}
}

func ruleList(f []types.Finding) string {
	var ids []string
	for _, x := range f {
		ids = append(ids, x.RuleID)
	}
	return strings.Join(ids, ", ")
}

// The catalog itself must stay well-formed: unique ids, a requirement on every
// policy, and no mapping onto a policy we declared out of scope (which would be
// coverage credit for something the report excludes from the denominator).
func TestSCuBACatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range SCuBACatalog() {
		if seen[p.ID] {
			t.Errorf("duplicate policy id %s", p.ID)
		}
		seen[p.ID] = true
		if p.Requirement == "" {
			t.Errorf("%s has no requirement text", p.ID)
		}
		if p.Product == "" {
			t.Errorf("%s has no product", p.ID)
		}
		if p.Covered() && p.Scope != ScopeDetectable {
			t.Errorf("%s is mapped to %v but scoped %s — credit outside the stated denominator",
				p.ID, p.Rules, p.Scope)
		}
	}
	if len(seen) < 100 {
		t.Errorf("catalog has only %d policies; the transcription looks truncated", len(seen))
	}
}

// The scorecard is the artifact a launch claim would cite, so it must render and
// state the neutral source + both denominators.
func TestSCuBAReportRenders(t *testing.T) {
	s := ScoreSCuBA(SCuBACatalog())
	out := RenderSCuBAReport(s, 12)
	for _, want := range []string{"ScubaGear", "ScubaGoggles", "scanner-detectable", "mandatory (SHALL) recall", "Not a SCuBA compliance claim"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	t.Logf("\n%s", out)
}
