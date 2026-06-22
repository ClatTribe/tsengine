// Package operate is the non-tech "run-secure" posture engine (Phase 4 of
// docs/autonomous-team.md) — the identity/email half a non-tech SMB lives on. It
// mirrors internal/cloudengine: a Workspace snapshot (an IdP / M365 / Google Workspace
// export) goes in, deterministic grounded findings come out. No live API and no LLM —
// every finding cites the exact user / domain / OAuth grant that triggered it, so it
// flows into the same store / grc / hitl loop as the engine's findings.
//
// Snapshot-in keeps the *logic* testable and honest (the anti-hallucination guard); a
// live Workspace connector that produces the snapshot is the follow-up, behind the same
// boundary cloudengine uses.
package operate

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Workspace is the snapshot of a non-tech org's identity + email estate.
type Workspace struct {
	Provider    string         `json:"provider"` // gworkspace | m365 | okta
	Org         string         `json:"org"`
	Users       []User         `json:"users"`
	Domains     []DomainConfig `json:"domains"`
	OAuthGrants []OAuthGrant   `json:"oauth_grants"`
}

// User is one workforce identity.
type User struct {
	Email         string `json:"email"`
	Admin         bool   `json:"admin"`
	SuperAdmin    bool   `json:"super_admin"`
	MFA           bool   `json:"mfa"`
	Suspended     bool   `json:"suspended"`
	LastLoginDays int    `json:"last_login_days"` // days since last login (0 = today)
}

// DomainConfig is the email-auth posture of a sending domain.
type DomainConfig struct {
	Name  string `json:"name"`
	DMARC string `json:"dmarc"` // none | quarantine | reject | "" (absent)
	SPF   bool   `json:"spf"`
	DKIM  bool   `json:"dkim"`
	// Depth signals (populated by the live resolver; absent/zero in snapshots → not asserted, so
	// the partial-strength checks never fire on a domain that didn't supply them).
	SPFAll   string `json:"spf_all,omitempty"`   // qualifier on the SPF `all` mechanism: - ~ ? + ("" = none/absent); + or ? is permissive
	DMARCPct int    `json:"dmarc_pct,omitempty"` // DMARC pct= (live: 100 when enforcing without an explicit pct); 0 = unknown
	DMARCSub string `json:"dmarc_sp,omitempty"`  // DMARC sp= subdomain policy ("" = inherits p)
}

// OAuthGrant is a third-party app granted access to the workspace.
type OAuthGrant struct {
	App        string   `json:"app"`
	Scopes     []string `json:"scopes"`
	Users      int      `json:"users"`       // how many users granted it
	AdminScope bool     `json:"admin_scope"` // holds an admin/directory-wide scope
	Verified   bool     `json:"verified"`    // publisher-verified by the provider
}

// Options bound the assessment.
type Options struct {
	StaleLoginDays int // a non-suspended account idle longer than this is stale (default 90)
	MaxSuperAdmins int // more super-admins than this is flagged (default 3)
	Now            time.Time
}

// Assess runs every grounded posture check over the workspace and returns the findings.
func Assess(ws Workspace, opts Options) []types.Finding {
	if opts.StaleLoginDays <= 0 {
		opts.StaleLoginDays = 90
	}
	if opts.MaxSuperAdmins <= 0 {
		opts.MaxSuperAdmins = 3
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	var f []types.Finding
	n := 0
	id := func() string { n++; return fmt.Sprintf("op-%03d", n) }

	f = append(f, checkAdminMFA(ws, now, id)...)
	f = append(f, checkUserMFA(ws, now, id)...)
	f = append(f, checkSuperAdmins(ws, opts.MaxSuperAdmins, now, id)...)
	f = append(f, checkStaleAccounts(ws, opts.StaleLoginDays, now, id)...)
	f = append(f, checkEmailAuth(ws, now, id)...)
	f = append(f, checkOAuthGrants(ws, now, id)...)
	return f
}

// --- checks (each is grounded: it cites the offending entity in Endpoint/Description) ---

// checkAdminMFA: an admin without MFA is the single highest-leverage non-tech risk.
func checkAdminMFA(ws Workspace, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, u := range ws.Users {
		if u.Suspended || !(u.Admin || u.SuperAdmin) || u.MFA {
			continue
		}
		out = append(out, finding(id(), "operate::admin-without-mfa", types.SeverityCritical,
			"Administrator without MFA: "+u.Email, u.Email,
			"Admin account "+u.Email+" has no multi-factor authentication. A stolen admin password = full takeover.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"},
				GDPR: []string{"Art. 32"}, NIST80053: []string{"IA-2", "AC-6"}, NIST800171: []string{"3.5.3", "3.1.5"},
				CCPA: []string{"1798.150"}, FedRAMP: []string{"IA-2", "AC-6"}, DPDP: []string{"Sec. 8(5)"}})))
	}
	return out
}

// checkUserMFA: workforce accounts without MFA (the phishing/credential-stuffing surface).
func checkUserMFA(ws Workspace, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, u := range ws.Users {
		if u.Suspended || u.Admin || u.SuperAdmin || u.MFA {
			continue
		}
		out = append(out, finding(id(), "operate::user-without-mfa", types.SeverityMedium,
			"User without MFA: "+u.Email, u.Email,
			"Account "+u.Email+" has no MFA; enforce org-wide MFA to close the #1 SMB breach vector.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"},
				GDPR: []string{"Art. 32"}, NIST80053: []string{"IA-2"}, NIST800171: []string{"3.5.3"},
				FedRAMP: []string{"IA-2"}, DPDP: []string{"Sec. 8(5)"}})))
	}
	return out
}

// checkSuperAdmins: too many super-admins widens the blast radius.
func checkSuperAdmins(ws Workspace, max int, now time.Time, id func() string) []types.Finding {
	var supers []string
	for _, u := range ws.Users {
		if u.SuperAdmin && !u.Suspended {
			supers = append(supers, u.Email)
		}
	}
	if len(supers) <= max {
		return nil
	}
	return []types.Finding{finding(id(), "operate::excess-super-admins", types.SeverityHigh,
		fmt.Sprintf("Too many super-admins (%d > %d)", len(supers), max), ws.Org,
		fmt.Sprintf("%d super-admins: %v. Reduce to the minimum and put the rest on least-privilege roles.", len(supers), supers),
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"},
			GDPR: []string{"Art. 32"}, NIST80053: []string{"AC-6"}, NIST800171: []string{"3.1.5"},
			FedRAMP: []string{"AC-6"}, DPDP: []string{"Sec. 8(5)"}}))}
}

// checkStaleAccounts: a live, idle account is an unguarded door.
func checkStaleAccounts(ws Workspace, staleDays int, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, u := range ws.Users {
		if u.Suspended || u.LastLoginDays <= staleDays {
			continue
		}
		sev := types.SeverityLow
		if u.Admin || u.SuperAdmin {
			sev = types.SeverityHigh // a stale ADMIN account is far worse
		}
		out = append(out, finding(id(), "operate::stale-account", sev,
			"Stale active account: "+u.Email, u.Email,
			fmt.Sprintf("%s has not logged in for %d days but is still active. Suspend or deprovision.", u.Email, u.LastLoginDays),
			now, comp(types.Compliance{SOC2: []string{"CC6.2"}, CISv8: []string{"5.3"},
				GDPR: []string{"Art. 32"}, NIST80053: []string{"AC-2"}, NIST800171: []string{"3.1.1"},
				FedRAMP: []string{"AC-2"}, DPDP: []string{"Sec. 8(5)"}})))
	}
	return out
}

// checkEmailAuth: weak DMARC/SPF/DKIM lets anyone spoof the org (BEC / phishing).
func checkEmailAuth(ws Workspace, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, d := range ws.Domains {
		if d.DMARC != "reject" && d.DMARC != "quarantine" {
			out = append(out, finding(id(), "operate::dmarc-not-enforced", types.SeverityHigh,
				"DMARC not enforced: "+d.Name, d.Name,
				"Domain "+d.Name+" has DMARC=\""+nz(d.DMARC, "absent")+"\". Without p=quarantine/reject, attackers can spoof your domain for BEC/phishing.",
				now, comp(types.Compliance{PCI: []string{"5.4.1"}, CISv8: []string{"9.5"},
					GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
		if !d.SPF || !d.DKIM {
			out = append(out, finding(id(), "operate::spf-dkim-missing", types.SeverityMedium,
				"SPF/DKIM incomplete: "+d.Name, d.Name,
				fmt.Sprintf("Domain %s: SPF=%t DKIM=%t. Both are prerequisites for DMARC enforcement.", d.Name, d.SPF, d.DKIM),
				now, comp(types.Compliance{CISv8: []string{"9.5"},
					GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
		// Depth: a permissive SPF `all` qualifier (+all / ?all) lets anyone pass SPF — present
		// but ineffective. Fires only on an explicitly-parsed permissive qualifier (FP-safe for
		// snapshot domains that don't supply SPFAll).
		if d.SPFAll == "+" || d.SPFAll == "?" {
			out = append(out, finding(id(), "operate::spf-permissive-all", types.SeverityMedium,
				"SPF permits any sender: "+d.Name, d.Name,
				fmt.Sprintf("Domain %s publishes SPF ending in %sall — it passes any sender, defeating SPF. Use -all (or ~all with DMARC).", d.Name, d.SPFAll),
				now, comp(types.Compliance{CISv8: []string{"9.5"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
		// Depth: DMARC enforcing but only on a fraction of mail (pct<100) — partial enforcement
		// that reads as "enforced". Fires only when pct was explicitly parsed (1..99).
		if (d.DMARC == "reject" || d.DMARC == "quarantine") && d.DMARCPct > 0 && d.DMARCPct < 100 {
			out = append(out, finding(id(), "operate::dmarc-partial-enforcement", types.SeverityMedium,
				"DMARC only partially enforced: "+d.Name, d.Name,
				fmt.Sprintf("Domain %s has p=%s but pct=%d — only %d%% of spoofed mail is acted on; the rest is delivered. Raise pct to 100.", d.Name, d.DMARC, d.DMARCPct, d.DMARCPct),
				now, comp(types.Compliance{PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
		// Depth: an enforcing p= but sp=none leaves SUBDOMAINS spoofable (a common BEC vector).
		// Fires only on an explicitly-parsed sp=none (FP-safe; absent sp inherits p).
		if (d.DMARC == "reject" || d.DMARC == "quarantine") && d.DMARCSub == "none" {
			out = append(out, finding(id(), "operate::dmarc-subdomain-unprotected", types.SeverityMedium,
				"DMARC subdomains unprotected: "+d.Name, d.Name,
				fmt.Sprintf("Domain %s enforces p=%s but sp=none — attackers can still spoof any subdomain (e.g. mail.%s). Set sp=reject.", d.Name, d.DMARC, d.Name),
				now, comp(types.Compliance{PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
	}
	return out
}

// checkOAuthGrants: an over-scoped third-party app is shadow-admin access.
func checkOAuthGrants(ws Workspace, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, g := range ws.OAuthGrants {
		switch {
		case g.AdminScope:
			out = append(out, finding(id(), "operate::oauth-admin-scope", types.SeverityCritical,
				"Third-party app with admin scope: "+g.App, g.App,
				fmt.Sprintf("App %q holds a directory/admin scope (%v) across %d users — effectively shadow-admin. Review and revoke if unneeded.", g.App, g.Scopes, g.Users),
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"},
					GDPR: []string{"Art. 32", "Art. 28"}, ISO27701: []string{"6.12"}, NIST80053: []string{"AC-6", "AC-3"},
					NIST800171: []string{"3.1.5"}, CCPA: []string{"1798.140"}, FedRAMP: []string{"AC-6"}, DPDP: []string{"Sec. 8(5)"}})))
		case !g.Verified && g.Users > 0:
			out = append(out, finding(id(), "operate::oauth-unverified-app", types.SeverityMedium,
				"Unverified third-party app granted access: "+g.App, g.App,
				fmt.Sprintf("Unverified app %q has %d users' data via %v. Confirm it's sanctioned.", g.App, g.Users, g.Scopes),
				now, comp(types.Compliance{CISv8: []string{"6.8"},
					GDPR: []string{"Art. 32", "Art. 28"}, NIST80053: []string{"AC-3"}, CCPA: []string{"1798.140"},
					FedRAMP: []string{"AC-3"}, DPDP: []string{"Sec. 8(5)"}})))
		}
	}
	return out
}

// --- helpers ---

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, c *types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "operate", Severity: sev,
		Title: title, Endpoint: endpoint, Description: desc,
		Compliance: c, DiscoveredAt: now,
		// grounded by a deterministic config fact, not a re-fired exploit:
		VerificationStatus: types.VerificationVerified,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
