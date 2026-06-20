package sspm

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// SlackWorkspace is a grounded snapshot of a Slack workspace's security
// configuration — the org/admin settings that carry a real control. Sourced
// from the Slack admin / SCIM APIs (or an exported snapshot). The second SSPM
// app (ADR 0004); reuses the package's finding/comp helpers.
type SlackWorkspace struct {
	Name                  string        `json:"name"`
	TwoFactorRequired     bool          `json:"two_factor_required"`     // workspace 2FA enforcement
	SSOEnforced           bool          `json:"sso_enforced"`            // SAML/SSO required for sign-in
	ApprovedAppsOnly      bool          `json:"approved_apps_only"`      // app-approval policy (only admins approve apps)
	PublicLinkSharing     bool          `json:"public_link_sharing"`     // external/public file-link sharing enabled
	InviteDomainAllowlist bool          `json:"invite_domain_allowlist"` // invites restricted to allowlisted domains
	Members               []SlackMember `json:"members"`
	Apps                  []SlackApp    `json:"apps"`
}

// SlackMember is one workspace member. Role ∈ owner|admin|member|guest.
type SlackMember struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	TwoFactor bool   `json:"two_factor"`
}

// SlackApp is an installed Slack app / integration.
type SlackApp struct {
	Name       string `json:"name"`
	Verified   bool   `json:"verified"`    // Slack-Marketplace approved / verified
	BroadScope bool   `json:"broad_scope"` // holds broad data scopes (read all channels/files, admin)
}

// AssessSlack runs every grounded posture check over a Slack workspace snapshot.
// A securely-configured workspace returns nil.
func AssessSlack(ws SlackWorkspace, opts Options) []types.Finding {
	if opts.MaxOwners <= 0 {
		opts.MaxOwners = 3
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-slack-%03d", n) }
	target := "slack:" + ws.Name

	var f []types.Finding
	f = append(f, slackCheck2FA(ws, target, now, id)...)
	f = append(f, slackCheckMember2FA(ws, target, now, id)...)
	f = append(f, slackCheckSSO(ws, target, now, id)...)
	f = append(f, slackCheckApprovedApps(ws, target, now, id)...)
	f = append(f, slackCheckApps(ws, target, now, id)...)
	f = append(f, slackCheckPublicSharing(ws, target, now, id)...)
	f = append(f, slackCheckGuests(ws, target, now, id)...)
	f = append(f, slackCheckAdminSprawl(ws, opts.MaxOwners, target, now, id)...)
	f = append(f, slackCheckInviteAllowlist(ws, target, now, id)...)
	return f
}

func slackCheck2FA(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	if ws.TwoFactorRequired || ws.SSOEnforced { // SSO providers carry MFA upstream
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::2fa-not-enforced", types.SeverityHigh,
		"Slack workspace does not require two-factor authentication", target,
		"Workspace 2FA enforcement is OFF and no SSO is required; a phished member password is workspace access.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func slackCheckMember2FA(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	if ws.TwoFactorRequired || ws.SSOEnforced {
		return nil
	}
	var out []types.Finding
	for _, m := range ws.Members {
		if m.TwoFactor || m.Role == "guest" {
			continue
		}
		sev := types.SeverityMedium
		if m.Role == "owner" || m.Role == "admin" {
			sev = types.SeverityHigh
		}
		out = append(out, finding(id(), "sspm::slack::member-without-2fa", sev,
			"Slack member without 2FA: "+m.Name, target+"/"+m.Name,
			"Member '"+m.Name+"' (role "+m.Role+") has no second factor enabled.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

func slackCheckSSO(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	if ws.SSOEnforced {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::sso-not-enforced", types.SeverityMedium,
		"Slack workspace does not enforce SSO/SAML sign-in", target,
		"Sign-in is not gated by your identity provider, so offboarding and central MFA/conditional-access policies do not apply.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.7"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func slackCheckApprovedApps(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	if ws.ApprovedAppsOnly {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::app-approval-disabled", types.SeverityMedium,
		"Slack workspace lets any member install apps (no approval policy)", target,
		"Without an app-approval policy any member can connect a third-party app with data access — an ungoverned data-egress path.",
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func slackCheckApps(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, a := range ws.Apps {
		switch {
		case a.BroadScope:
			out = append(out, finding(id(), "sspm::slack::app-broad-scope", types.SeverityHigh,
				"Installed Slack app holds broad data scopes: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' can read across channels/files (or admin); confirm it is needed and trusted — a third-party data-exfil surface.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8", "16.11"}, GDPR: []string{"Art. 32"}})))
		case !a.Verified:
			out = append(out, finding(id(), "sspm::slack::app-unverified", types.SeverityMedium,
				"Installed Slack app is not Marketplace-verified: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' is not verified by Slack; review its access and provenance.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}})))
		}
	}
	return out
}

func slackCheckPublicSharing(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	if !ws.PublicLinkSharing {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::public-link-sharing", types.SeverityMedium,
		"Slack workspace allows public/external file-link sharing", target,
		"Files can be shared via public links reachable without authentication — a data-exposure path. Restrict to org-only sharing.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, GDPR: []string{"Art. 32"}, CCPA: []string{"1798.150"}}))}
}

func slackCheckGuests(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	guests := 0
	for _, m := range ws.Members {
		if m.Role == "guest" {
			guests++
		}
	}
	if guests == 0 {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::guest-accounts", types.SeverityLow,
		fmt.Sprintf("Slack workspace has %d guest account(s)", guests), target,
		"External guest accounts have channel access; review periodically and remove stale guests.",
		now, comp(types.Compliance{SOC2: []string{"CC6.2"}, CISv8: []string{"6.8"}}))}
}

func slackCheckAdminSprawl(ws SlackWorkspace, max int, target string, now time.Time, id func() string) []types.Finding {
	admins := 0
	for _, m := range ws.Members {
		if m.Role == "owner" || m.Role == "admin" {
			admins++
		}
	}
	if admins <= max {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::admin-sprawl", types.SeverityMedium,
		fmt.Sprintf("Slack workspace has %d owners/admins (admin sprawl)", admins), target,
		fmt.Sprintf("%d members hold owner/admin (> recommended %d); each is broad workspace control. Reduce to the minimum.", admins, max),
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func slackCheckInviteAllowlist(ws SlackWorkspace, target string, now time.Time, id func() string) []types.Finding {
	if ws.InviteDomainAllowlist {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::slack::no-invite-domain-allowlist", types.SeverityLow,
		"Slack workspace does not restrict invites to allowlisted domains", target,
		"Invitations are not domain-restricted, so a member can invite arbitrary external addresses. Configure an invite domain allowlist.",
		now, comp(types.Compliance{SOC2: []string{"CC6.2"}, CISv8: []string{"6.8"}}))}
}
