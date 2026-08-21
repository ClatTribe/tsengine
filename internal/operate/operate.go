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
	// Unavailable names the parts of this workspace's posture that could NOT be read —
	// a scope the customer has not consented to, an API that failed, a capability the
	// provider does not expose. It is the workspace twin of DomainConfig.Unresolved, and
	// it exists for the same reason.
	//
	// THE ZERO VALUES CANNOT TELL THE TWO CASES APART. A tenant with no risky OAuth apps
	// and a tenant whose grant read was never consented to both arrive here with
	// OAuthGrants empty — and the second one then reads, on the customer's screen, as a
	// clean OAuth posture. That is the most valuable finding this engine produces (a
	// shadow-admin third-party app is critical) reported as its own opposite.
	//
	// Values: "oauth_grants", "mfa", "users". Empty for posted snapshots, which assert
	// their values directly — so snapshot behaviour is unchanged and this is additive.
	Unavailable []string `json:"unavailable,omitempty"`
	// ProviderLimits names checks this PROVIDER cannot support at all, as opposed to ones
	// that failed. Distinct from Unavailable because the remedy differs: an unavailable
	// read is fixed by granting a scope, a provider limit is not fixable and needs another
	// route entirely. Telling a customer to grant a permission that would not help is
	// worse than saying nothing.
	ProviderLimits []string `json:"provider_limits,omitempty"`
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
	// Unresolved names the lookups that could NOT be answered — a DNS timeout, SERVFAIL or a dead
	// network — as distinct from a definitive "no such record".
	//
	// The zero values cannot tell those apart on their own: a domain that genuinely publishes no
	// DMARC and a domain whose lookup timed out both arrive here as DMARC="". Reporting the second
	// as "DMARC not enforced" asserts a security failing that was never observed, which is the one
	// thing this engine is not allowed to do (§10). A field named here is UNKNOWN, and every check
	// reading it must skip rather than fire.
	//
	// Empty for posted snapshots, which assert their values directly — so snapshot behaviour is
	// unchanged and this is purely additive.
	Unresolved []string `json:"unresolved,omitempty"` // any of: "dmarc", "spf", "dkim"
}

// Unknown reports whether a given email-auth lookup could not be answered, letting callers tell
// "we looked and it is absent" (a finding) from "we could not look" (not a finding).
func (d DomainConfig) Unknown(field string) bool {
	for _, f := range d.Unresolved {
		if f == field {
			return true
		}
	}
	return false
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
	f = append(f, checkIncompleteOffboarding(ws, now, id)...)
	f = append(f, checkEmailAuth(ws, now, id)...)
	f = append(f, checkOAuthGrants(ws, now, id)...)
	// Coverage disclosure LAST. What this scan could not check is part of its result: a
	// grant read that never ran and a workspace with no risky apps produce the same empty
	// list, and only one of them means the customer is safe.
	f = append(f, CoverageGaps(ws, now)...)
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
				CCPA: []string{"1798.150"}, FedRAMP: []string{"IA-2", "AC-6"}, DPDP: []string{"Sec. 8(5)"},
				HIPAA: []string{"164.312(d)"}, ISO27001: []string{"A.5.17"}, SOX: []string{"ITGC: Access to Programs & Data"}})))
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
				FedRAMP: []string{"IA-2"}, DPDP: []string{"Sec. 8(5)"},
				HIPAA: []string{"164.312(d)"}, ISO27001: []string{"A.5.17"}, SOX: []string{"ITGC: Access to Programs & Data"}})))
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
			FedRAMP: []string{"AC-6"}, DPDP: []string{"Sec. 8(5)"},
			HIPAA: []string{"164.312(a)(1)"}, ISO27001: []string{"A.5.15", "A.8.2"}, SOX: []string{"ITGC: Access to Programs & Data"}}))}
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
				FedRAMP: []string{"AC-2"}, DPDP: []string{"Sec. 8(5)"},
				HIPAA: []string{"164.312(a)(1)"}, ISO27001: []string{"A.5.16"}, SOX: []string{"ITGC: Access to Programs & Data"}})))
	}
	return out
}

// checkIncompleteOffboarding: a SUSPENDED account that still holds admin/super-admin role bindings — standing
// privilege that survived the disable. Every other check skips suspended accounts, so this blind spot (an
// ex-employee whose admin role was never stripped) is otherwise invisible. Re-enabling the account = instant
// admin, and it signals the offboarding runbook didn't complete. Grounded: cites the suspended-yet-privileged
// account. The Nudge/Wing/Push "deprovisioning completeness" signal, over the identity data we already hold.
func checkIncompleteOffboarding(ws Workspace, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, u := range ws.Users {
		if !u.Suspended || !(u.Admin || u.SuperAdmin) {
			continue
		}
		role := "admin"
		sev := types.SeverityMedium
		if u.SuperAdmin {
			role, sev = "super-admin", types.SeverityHigh // a lingering super-admin binding is worse
		}
		out = append(out, finding(id(), "operate::incomplete-offboarding", sev,
			"Suspended account retains "+role+" role: "+u.Email, u.Email,
			fmt.Sprintf("%s is suspended but still holds a %s role binding — standing privilege that outlived the account disable. Re-enabling it grants instant %s, and it shows the offboarding runbook didn't strip roles. Remove the role (and revoke its OAuth grants/API tokens) before or with the suspend.", u.Email, role, role),
			now, comp(types.Compliance{SOC2: []string{"CC6.2", "CC6.3"}, CISv8: []string{"5.3", "6.8"},
				GDPR: []string{"Art. 32"}, NIST80053: []string{"AC-2", "AC-6"}, NIST800171: []string{"3.1.1", "3.1.5"},
				FedRAMP: []string{"AC-2", "AC-6"}, DPDP: []string{"Sec. 8(5)"},
				HIPAA: []string{"164.312(a)(1)"}, ISO27001: []string{"A.5.16", "A.5.18"}, SOX: []string{"ITGC: Access to Programs & Data"}})))
	}
	return out
}

// checkEmailAuth: weak DMARC/SPF/DKIM lets anyone spoof the org (BEC / phishing).
func checkEmailAuth(ws Workspace, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, d := range ws.Domains {
		// A lookup that could not be answered is UNKNOWN, not absent. Firing here would tell a
		// customer their domain is spoofable because our resolver timed out — a finding we never
		// observed, on the posture page they act from.
		if !d.Unknown("dmarc") && d.DMARC != "reject" && d.DMARC != "quarantine" {
			out = append(out, finding(id(), "operate::dmarc-not-enforced", types.SeverityHigh,
				"DMARC not enforced: "+d.Name, d.Name,
				"Domain "+d.Name+" has DMARC=\""+nz(d.DMARC, "absent")+"\". Without p=quarantine/reject, attackers can spoof your domain for BEC/phishing.",
				now, comp(types.Compliance{PCI: []string{"5.4.1"}, CISv8: []string{"9.5"},
					GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
		// Same rule: only assert a gap in a record we actually resolved. If either lookup went
		// unanswered the pair is inconclusive, because the finding names both.
		if !d.Unknown("spf") && !d.Unknown("dkim") && (!d.SPF || !d.DKIM) {
			out = append(out, finding(id(), "operate::spf-dkim-missing", types.SeverityMedium,
				"SPF/DKIM incomplete: "+d.Name, d.Name,
				fmt.Sprintf("Domain %s: SPF=%t DKIM=%t. Both are prerequisites for DMARC enforcement.", d.Name, d.SPF, d.DKIM),
				now, comp(types.Compliance{CISv8: []string{"9.5"},
					GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
		}
		// Depth: DMARC is published and enforcing, but at p=quarantine rather than p=reject —
		// spoofed mail still reaches the recipient's junk folder instead of being rejected, and
		// quarantine is the usual "we started a DMARC rollout and stopped" resting state. CISA's
		// SCuBA baselines (MS.EXO.4.2v1 / GWS.GMAIL.4.2v1) make p=reject mandatory. Fires only on
		// an explicitly-parsed quarantine, so an absent DMARC still gets the high-severity
		// not-enforced finding above and a p=reject domain stays clean (no double-report).
		if d.DMARC == "quarantine" {
			out = append(out, finding(id(), "operate::dmarc-not-rejecting", types.SeverityMedium,
				"DMARC quarantines but does not reject: "+d.Name, d.Name,
				fmt.Sprintf("Domain %s publishes p=quarantine. Spoofed mail is still delivered (to junk) rather than rejected, so BEC/phishing can land. Move to p=reject once the aggregate reports are clean.", d.Name),
				now, comp(types.Compliance{PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}})))
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
					NIST800171: []string{"3.1.5"}, CCPA: []string{"1798.140"}, FedRAMP: []string{"AC-6"}, DPDP: []string{"Sec. 8(5)"},
					HIPAA: []string{"164.312(a)(1)"}, ISO27001: []string{"A.5.15"}, SOX: []string{"ITGC: Access to Programs & Data"}})))
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
