package sspm

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// SalesforceOrg is a grounded snapshot of a Salesforce org's security configuration — the org/admin
// settings that carry a real control. Sourced from the Salesforce Setup / Security Health Check /
// Metadata APIs (or an exported snapshot). The fifth SSPM app (ADR 0004), completing the named set
// (GitHub, Slack, Zoom, Atlassian, Salesforce). A securely-configured org yields ZERO findings.
//
// Salesforce-distinct risks this catches: public Experience Cloud (Community) GUEST access — the
// notorious Salesforce data-exposure misconfig — broad-scope connected (OAuth) apps, and
// Modify-All-Data permission sprawl.
type SalesforceOrg struct {
	Name             string                `json:"name"`
	MFARequired      bool                  `json:"mfa_required"`       // org-wide MFA enforcement
	SSOEnforced      bool                  `json:"sso_enforced"`       // SAML/SSO required for sign-in
	IPRestrictions   bool                  `json:"ip_restrictions"`    // login IP ranges configured
	ApprovedAppsOnly bool                  `json:"approved_apps_only"` // admin-approved connected apps only
	Users            []SalesforceUser      `json:"users"`
	ConnectedApps    []SalesforceApp       `json:"connected_apps"`
	Communities      []SalesforceCommunity `json:"communities"`
}

// SalesforceUser is one org user. Profile "System Administrator" is the admin role.
type SalesforceUser struct {
	Username      string `json:"username"`
	Profile       string `json:"profile"`
	MFA           bool   `json:"mfa"`
	ModifyAllData bool   `json:"modify_all_data"` // the dangerous "Modify All Data" permission
}

// SalesforceApp is an installed connected (OAuth) app.
type SalesforceApp struct {
	Name       string `json:"name"`
	Verified   bool   `json:"verified"`    // admin-reviewed / AppExchange-listed
	BroadScope bool   `json:"broad_scope"` // holds 'full' or 'api' OAuth scope (read/write all data)
}

// SalesforceCommunity is one Experience Cloud (Community) site — the public-access exposure surface.
type SalesforceCommunity struct {
	Name        string `json:"name"`
	GuestAccess bool   `json:"guest_access"` // guest/public (unauthenticated) access enabled
}

// AssessSalesforce runs every grounded posture check over a Salesforce org snapshot.
// A securely-configured org returns nil.
func AssessSalesforce(org SalesforceOrg, opts Options) []types.Finding {
	if opts.MaxOwners <= 0 {
		opts.MaxOwners = 3
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-salesforce-%03d", n) }
	target := "salesforce:" + org.Name

	var f []types.Finding
	f = append(f, sfCheckMFA(org, target, now, id)...)
	f = append(f, sfCheckUserMFA(org, target, now, id)...)
	f = append(f, sfCheckSSO(org, target, now, id)...)
	f = append(f, sfCheckIPRestrictions(org, target, now, id)...)
	f = append(f, sfCheckGuestAccess(org, target, now, id)...)
	f = append(f, sfCheckModifyAllData(org, target, now, id)...)
	f = append(f, sfCheckApprovedApps(org, target, now, id)...)
	f = append(f, sfCheckApps(org, target, now, id)...)
	f = append(f, sfCheckAdminSprawl(org, opts.MaxOwners, target, now, id)...)
	return f
}

func sfCheckMFA(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.MFARequired || org.SSOEnforced {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::salesforce::mfa-not-enforced", types.SeverityHigh,
		"Salesforce org does not require multi-factor authentication", target,
		"Org MFA enforcement is OFF and no SSO is required; a phished user password is access to your CRM data.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func sfCheckUserMFA(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.MFARequired || org.SSOEnforced {
		return nil
	}
	var out []types.Finding
	for _, u := range org.Users {
		if u.MFA {
			continue
		}
		sev := types.SeverityMedium
		if u.Profile == "System Administrator" {
			sev = types.SeverityHigh
		}
		out = append(out, finding(id(), "sspm::salesforce::user-without-mfa", sev,
			"Salesforce user without MFA: "+u.Username, target+"/"+u.Username,
			"User '"+u.Username+"' (profile "+u.Profile+") has no second factor enabled.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

func sfCheckSSO(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.SSOEnforced {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::salesforce::sso-not-enforced", types.SeverityMedium,
		"Salesforce org does not enforce SSO/SAML sign-in", target,
		"Sign-in is not gated by your identity provider, so offboarding and central MFA/conditional-access policies do not apply.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.7"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func sfCheckIPRestrictions(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.IPRestrictions {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::salesforce::no-ip-restrictions", types.SeverityMedium,
		"Salesforce org has no login IP-range restrictions", target,
		"Logins are accepted from any IP; profile/org login-IP ranges limit where a stolen credential can be used. Configure trusted IP ranges.",
		now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"12.7"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func sfCheckGuestAccess(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, c := range org.Communities {
		if !c.GuestAccess {
			continue
		}
		out = append(out, finding(id(), "sspm::salesforce::community-guest-access", types.SeverityHigh,
			"Salesforce Experience Cloud site allows guest (public) access: "+c.Name, target+"/communities/"+c.Name,
			"Community '"+c.Name+"' has guest/unauthenticated access enabled; misconfigured guest sharing is the well-known Salesforce data-exposure path (records readable without login). Audit guest-user object/field permissions and sharing.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, GDPR: []string{"Art. 32"}, CCPA: []string{"1798.150"}})))
	}
	return out
}

func sfCheckModifyAllData(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, u := range org.Users {
		if !u.ModifyAllData || u.Profile == "System Administrator" {
			continue // admins legitimately hold it; flag it on NON-admin profiles (privilege sprawl)
		}
		out = append(out, finding(id(), "sspm::salesforce::modify-all-data", types.SeverityHigh,
			"Non-admin Salesforce user holds 'Modify All Data': "+u.Username, target+"/"+u.Username,
			"User '"+u.Username+"' (profile "+u.Profile+") has the 'Modify All Data' permission without being a System Administrator — effectively full data control. Remove it or move to a scoped permission set.",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}})))
	}
	return out
}

func sfCheckApprovedApps(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.ApprovedAppsOnly {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::salesforce::app-approval-disabled", types.SeverityMedium,
		"Salesforce org lets users authorize connected apps without admin approval", target,
		"Without admin pre-approval any user can authorize a third-party connected (OAuth) app with data access — an ungoverned data-egress path. Set connected apps to admin-approved-users-only.",
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func sfCheckApps(org SalesforceOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, a := range org.ConnectedApps {
		switch {
		case a.BroadScope:
			out = append(out, finding(id(), "sspm::salesforce::app-broad-scope", types.SeverityHigh,
				"Connected Salesforce app holds broad OAuth scope: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' holds a 'full' or 'api' scope (read/write all data); confirm it is needed and trusted — a third-party data-exfil surface.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8", "16.11"}, GDPR: []string{"Art. 32"}})))
		case !a.Verified:
			out = append(out, finding(id(), "sspm::salesforce::app-unverified", types.SeverityMedium,
				"Connected Salesforce app is unverified: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' has not been admin-reviewed / is not AppExchange-listed; review its access and provenance.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}})))
		}
	}
	return out
}

func sfCheckAdminSprawl(org SalesforceOrg, max int, target string, now time.Time, id func() string) []types.Finding {
	admins := 0
	for _, u := range org.Users {
		if u.Profile == "System Administrator" {
			admins++
		}
	}
	if admins <= max {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::salesforce::admin-sprawl", types.SeverityMedium,
		fmt.Sprintf("Salesforce org has %d System Administrators (admin sprawl)", admins), target,
		fmt.Sprintf("%d users hold the System Administrator profile (> recommended %d); each is full org control. Reduce to the minimum.", admins, max),
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}
