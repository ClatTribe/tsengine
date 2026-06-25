package sspm

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// AtlassianOrg is a grounded snapshot of an Atlassian (Jira / Confluence) organization's security
// configuration — the org/admin settings that carry a real control. Sourced from the Atlassian
// admin / Access APIs (or an exported snapshot). The fourth SSPM app (ADR 0004, after GitHub +
// Slack + Zoom); reuses the package's finding/comp helpers. A securely-configured org yields ZERO
// findings (the testability invariant). Distinct Atlassian risks: public Confluence spaces (doc
// exposure) and user API tokens that bypass SSO/MFA.
type AtlassianOrg struct {
	Name              string            `json:"name"`
	TwoFactorRequired bool              `json:"two_factor_required"` // org 2FA enforcement (Atlassian Access)
	SSOEnforced       bool              `json:"sso_enforced"`        // SAML/SSO via Atlassian Access
	PublicSignup      bool              `json:"public_signup"`       // anyone with a verified-domain email can self-join
	ApprovedAppsOnly  bool              `json:"approved_apps_only"`  // Marketplace app install requires admin approval
	Members           []AtlassianMember `json:"members"`
	Apps              []AtlassianApp    `json:"apps"`
	Spaces            []ConfluenceSpace `json:"spaces"`
}

// AtlassianMember is one org user. Role ∈ admin (org/site admin) | member.
type AtlassianMember struct {
	Email     string `json:"email"`
	Role      string `json:"role"`
	TwoFactor bool   `json:"two_factor"`
	APIToken  bool   `json:"api_token"` // holds a long-lived user API token (bypasses SSO/MFA)
}

// AtlassianApp is an installed Marketplace app / integration.
type AtlassianApp struct {
	Name       string `json:"name"`
	Verified   bool   `json:"verified"`    // Marketplace "Cloud Fortified" / verified vendor
	BroadScope bool   `json:"broad_scope"` // read/write across all projects/spaces, or admin
}

// ConfluenceSpace is one Confluence space (the public-access exposure surface).
type ConfluenceSpace struct {
	Key          string `json:"key"`
	PublicAccess bool   `json:"public_access"` // anonymous/public access enabled
}

// AssessAtlassian runs every grounded posture check over an Atlassian org snapshot.
// A securely-configured org returns nil.
func AssessAtlassian(org AtlassianOrg, opts Options) []types.Finding {
	if opts.MaxOwners <= 0 {
		opts.MaxOwners = 3
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-atlassian-%03d", n) }
	target := "atlassian:" + org.Name

	var f []types.Finding
	f = append(f, atlCheck2FA(org, target, now, id)...)
	f = append(f, atlCheckMember2FA(org, target, now, id)...)
	f = append(f, atlCheckSSO(org, target, now, id)...)
	f = append(f, atlCheckPublicSignup(org, target, now, id)...)
	f = append(f, atlCheckPublicSpaces(org, target, now, id)...)
	f = append(f, atlCheckAPITokens(org, target, now, id)...)
	f = append(f, atlCheckApprovedApps(org, target, now, id)...)
	f = append(f, atlCheckApps(org, target, now, id)...)
	f = append(f, atlCheckAdminSprawl(org, opts.MaxOwners, target, now, id)...)
	return f
}

func atlCheck2FA(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.TwoFactorRequired || org.SSOEnforced {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::atlassian::2fa-not-enforced", types.SeverityHigh,
		"Atlassian org does not require two-factor authentication", target,
		"Org 2FA enforcement is OFF and no SSO is required; a phished user password is access to Jira/Confluence.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func atlCheckMember2FA(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.TwoFactorRequired || org.SSOEnforced {
		return nil
	}
	var out []types.Finding
	for _, m := range org.Members {
		if m.TwoFactor {
			continue
		}
		sev := types.SeverityMedium
		if m.Role == "admin" {
			sev = types.SeverityHigh
		}
		out = append(out, finding(id(), "sspm::atlassian::member-without-2fa", sev,
			"Atlassian user without 2FA: "+m.Email, target+"/"+m.Email,
			"User '"+m.Email+"' (role "+m.Role+") has no second factor enabled.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

func atlCheckSSO(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.SSOEnforced {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::atlassian::sso-not-enforced", types.SeverityMedium,
		"Atlassian org does not enforce SSO/SAML (Atlassian Access)", target,
		"Sign-in is not gated by your identity provider, so offboarding and central MFA/conditional-access policies do not apply.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.7"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func atlCheckPublicSignup(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	if !org.PublicSignup {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::atlassian::public-signup", types.SeverityMedium,
		"Atlassian org allows open/self sign-up", target,
		"Anyone with a verified-domain email can self-join the org without admin approval — an uncontrolled access path. Require admin approval for new members.",
		now, comp(types.Compliance{SOC2: []string{"CC6.2"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func atlCheckPublicSpaces(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, s := range org.Spaces {
		if !s.PublicAccess {
			continue
		}
		out = append(out, finding(id(), "sspm::atlassian::confluence-public-space", types.SeverityHigh,
			"Confluence space is publicly accessible: "+s.Key, target+"/spaces/"+s.Key,
			"Space '"+s.Key+"' has anonymous/public access enabled; its pages are readable without authentication — a documentation data-exposure path. Restrict to org members.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, GDPR: []string{"Art. 32"}, CCPA: []string{"1798.150"}})))
	}
	return out
}

func atlCheckAPITokens(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, m := range org.Members {
		if !m.APIToken {
			continue
		}
		out = append(out, finding(id(), "sspm::atlassian::user-api-token", types.SeverityMedium,
			"Atlassian user holds a long-lived API token: "+m.Email, target+"/"+m.Email,
			"User '"+m.Email+"' has a personal API token; these bypass SSO/MFA and don't expire on offboarding. Review + rotate, and prefer scoped/OAuth access.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5", "5.4"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

func atlCheckApprovedApps(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.ApprovedAppsOnly {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::atlassian::app-approval-disabled", types.SeverityMedium,
		"Atlassian org lets any user install Marketplace apps (no approval)", target,
		"Without app-install approval any user can connect a third-party app with project/space data access — an ungoverned data-egress path.",
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func atlCheckApps(org AtlassianOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, a := range org.Apps {
		switch {
		case a.BroadScope:
			out = append(out, finding(id(), "sspm::atlassian::app-broad-scope", types.SeverityHigh,
				"Installed Atlassian app holds broad data scopes: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' can read/write across all projects/spaces (or admin); confirm it is needed and trusted — a third-party data-exfil surface.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8", "16.11"}, GDPR: []string{"Art. 32"}})))
		case !a.Verified:
			out = append(out, finding(id(), "sspm::atlassian::app-unverified", types.SeverityMedium,
				"Installed Atlassian app is not a verified/Cloud-Fortified vendor: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' is not Marketplace-verified (Cloud Fortified); review its access and provenance.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}})))
		}
	}
	return out
}

func atlCheckAdminSprawl(org AtlassianOrg, max int, target string, now time.Time, id func() string) []types.Finding {
	admins := 0
	for _, m := range org.Members {
		if m.Role == "admin" {
			admins++
		}
	}
	if admins <= max {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::atlassian::admin-sprawl", types.SeverityMedium,
		fmt.Sprintf("Atlassian org has %d admins (admin sprawl)", admins), target,
		fmt.Sprintf("%d users hold org/site admin (> recommended %d); each is broad control over Jira/Confluence. Reduce to the minimum.", admins, max),
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}
