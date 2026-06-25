// Package sspm is the SaaS Security Posture Management engine — the
// configuration-posture half of the non-tech surface, sibling to internal/operate
// (which covers identity / email posture for the IdPs). operate answers "who can
// log in and how"; sspm answers "is each SaaS app you run configured securely".
//
// Same architecture as operate (and the deterministic cloudengine): a SNAPSHOT
// of the app's security configuration → grounded checks → findings mapped to
// compliance controls → the same store / grc / hitl / ledger loop. It is
// LLM-free and deterministic, so a hardened app yields ZERO findings (the
// testability invariant) and every finding cites the offending setting/entity.
//
// Top SaaS apps to support (priority, see docs/adr/0004): GitHub org (built
// here) + Slack (slack.go) — highest value for a dev SMB — then Atlassian
// (Jira/Confluence), Zoom, Salesforce. Google Workspace / Microsoft 365 / Okta
// identity posture is already covered by internal/operate. Each new app is one
// snapshot type + its Assess* function, exactly like adding a check to operate.
package sspm

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// GitHubOrg is a grounded snapshot of a GitHub organization's security
// configuration — the fields that carry a real security control. Sourced from
// the GitHub org/admin API (or an exported snapshot); the engine never guesses.
type GitHubOrg struct {
	Login                       string       `json:"login"`
	TwoFactorRequired           bool         `json:"two_factor_required"`     // org-wide 2FA enforcement
	DefaultRepoPermission       string       `json:"default_repo_permission"` // none|read|write|admin
	MembersCanCreatePublicRepos bool         `json:"members_can_create_public_repos"`
	SecretScanningEnabled       bool         `json:"secret_scanning_enabled"` // org default: secret scanning + push protection
	Members                     []OrgMember  `json:"members"`
	OutsideCollaborators        []OrgMember  `json:"outside_collaborators"`
	Apps                        []OrgApp     `json:"apps"`     // installed OAuth / GitHub Apps
	Webhooks                    []OrgWebhook `json:"webhooks"` // org-level webhooks
}

// OrgMember is one org member or outside collaborator.
type OrgMember struct {
	Login     string `json:"login"`
	Role      string `json:"role"` // "member" | "admin" (org owner)
	TwoFactor bool   `json:"two_factor"`
}

// OrgApp is an installed third-party OAuth app / GitHub App.
type OrgApp struct {
	Name            string `json:"name"`
	Verified        bool   `json:"verified"`         // publisher-verified by GitHub
	AdminPermission bool   `json:"admin_permission"` // holds org-admin / write-all scope
}

// OrgWebhook is an org-level webhook.
type OrgWebhook struct {
	URL       string `json:"url"`
	SSLVerify bool   `json:"ssl_verify"`
	Active    bool   `json:"active"`
}

// Options tunes the thresholds.
type Options struct {
	MaxOwners int // more org owners than this is admin sprawl (default 3)
	Now       time.Time
}

// AssessGitHubOrg runs every grounded posture check over a GitHub org snapshot
// and returns the findings. A securely-configured org returns nil.
func AssessGitHubOrg(org GitHubOrg, opts Options) []types.Finding {
	if opts.MaxOwners <= 0 {
		opts.MaxOwners = 3
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-%03d", n) }
	target := "github:" + org.Login

	var f []types.Finding
	f = append(f, checkOrg2FA(org, target, now, id)...)
	f = append(f, checkMember2FA(org, target, now, id)...)
	f = append(f, checkDefaultRepoPermission(org, target, now, id)...)
	f = append(f, checkPublicRepoCreation(org, target, now, id)...)
	f = append(f, checkSecretScanning(org, target, now, id)...)
	f = append(f, checkOutsideCollaborators(org, target, now, id)...)
	f = append(f, checkOwnerSprawl(org, opts.MaxOwners, target, now, id)...)
	f = append(f, checkApps(org, target, now, id)...)
	f = append(f, checkWebhooks(org, target, now, id)...)
	return f
}

// --- checks (each grounded: cites the offending setting/entity) ---

// checkOrg2FA: org-wide 2FA enforcement is the single highest-leverage GitHub
// org control — without it a phished member password is account takeover.
func checkOrg2FA(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.TwoFactorRequired {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::github::2fa-not-enforced", types.SeverityHigh,
		"GitHub org does not require two-factor authentication", target,
		"The organization's 'Require two-factor authentication' setting is OFF; a single phished member credential is org access.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, ISO27001: []string{"A.5.17"}}))}
}

// checkMember2FA: when enforcement is off, each member without 2FA is a concrete
// gap (cited by login). Skipped when enforcement is on (the org control covers it).
func checkMember2FA(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.TwoFactorRequired {
		return nil
	}
	var out []types.Finding
	for _, m := range org.Members {
		if m.TwoFactor {
			continue
		}
		sev := types.SeverityMedium
		if m.Role == "admin" {
			sev = types.SeverityHigh // an org owner without 2FA is the worst case
		}
		out = append(out, finding(id(), "sspm::github::member-without-2fa", sev,
			"GitHub org member without 2FA: "+m.Login, target+"/"+m.Login,
			"Member '"+m.Login+"' (role "+roleLabel(m.Role)+") has no second factor enabled.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

// checkDefaultRepoPermission: a base permission of write/admin means every member
// can change (or administer) every repo — a least-privilege violation.
func checkDefaultRepoPermission(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	switch org.DefaultRepoPermission {
	case "write", "admin":
		return []types.Finding{finding(id(), "sspm::github::broad-default-repo-permission", types.SeverityMedium,
			"GitHub org grants every member '"+org.DefaultRepoPermission+"' on all repositories", target,
			"Base repository permission is '"+org.DefaultRepoPermission+"'; least privilege wants 'read' or 'none' with per-team grants.",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"3.3", "6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
	}
	return nil
}

// checkPublicRepoCreation: members creating public repos at will is a data-exposure path.
func checkPublicRepoCreation(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	if !org.MembersCanCreatePublicRepos {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::github::members-can-create-public-repos", types.SeverityMedium,
		"GitHub org members can create public repositories", target,
		"Any member can publish a public repository, a common source-code / secret exposure path. Restrict public repo creation to owners.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, GDPR: []string{"Art. 32"}}))}
}

// checkSecretScanning: secret scanning + push protection off → leaked credentials
// land in history (the #1 real GitHub incident).
func checkSecretScanning(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.SecretScanningEnabled {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::github::secret-scanning-disabled", types.SeverityHigh,
		"GitHub org secret scanning / push protection is not enabled by default", target,
		"New repositories do not get secret scanning + push protection, so a pushed API key / token is not caught at the door.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.DS-01"}, PCI: []string{"6.3.1"}}))}
}

// checkOutsideCollaborators: external accounts with repo access — review surface.
func checkOutsideCollaborators(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	if len(org.OutsideCollaborators) == 0 {
		return nil
	}
	names := make([]string, 0, len(org.OutsideCollaborators))
	for _, c := range org.OutsideCollaborators {
		names = append(names, c.Login)
	}
	return []types.Finding{finding(id(), "sspm::github::outside-collaborators", types.SeverityLow,
		fmt.Sprintf("GitHub org has %d outside collaborator(s)", len(org.OutsideCollaborators)), target,
		"External accounts with repository access (review periodically): "+joinNames(names)+".",
		now, comp(types.Compliance{SOC2: []string{"CC6.2"}, CISv8: []string{"6.8"}}))}
}

// checkOwnerSprawl: too many org owners widens the blast radius of any one takeover.
func checkOwnerSprawl(org GitHubOrg, max int, target string, now time.Time, id func() string) []types.Finding {
	owners := 0
	for _, m := range org.Members {
		if m.Role == "admin" {
			owners++
		}
	}
	if owners <= max {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::github::owner-sprawl", types.SeverityMedium,
		fmt.Sprintf("GitHub org has %d owners (admin sprawl)", owners), target,
		fmt.Sprintf("%d members hold the org-owner role (> recommended %d); each is full org control. Reduce to the minimum.", owners, max),
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}

// checkApps: an unverified-publisher app, or one holding org-admin scope, is the
// third-party / shadow-admin risk (mirrors operate's OAuth-grant checks).
func checkApps(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, a := range org.Apps {
		switch {
		case a.AdminPermission:
			out = append(out, finding(id(), "sspm::github::app-admin-scope", types.SeverityHigh,
				"Installed GitHub app holds org-admin scope: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' can administer the organization — a third-party shadow-admin. Confirm it is needed and trusted.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8", "16.11"}, NISTCSF: []string{"PR.AA-05"}})))
		case !a.Verified:
			out = append(out, finding(id(), "sspm::github::app-unverified", types.SeverityMedium,
				"Installed GitHub app from an unverified publisher: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' is not from a verified publisher; review its access and provenance.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}})))
		}
	}
	return out
}

// checkWebhooks: a webhook without SSL verification leaks payloads (often
// containing code/secrets) to a MITM.
func checkWebhooks(org GitHubOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, w := range org.Webhooks {
		if !w.Active || w.SSLVerify {
			continue
		}
		out = append(out, finding(id(), "sspm::github::webhook-no-ssl-verify", types.SeverityMedium,
			"GitHub org webhook without SSL verification", target+"/hooks",
			"Webhook to '"+w.URL+"' has SSL verification disabled; its payloads can be intercepted or spoofed.",
			now, comp(types.Compliance{SOC2: []string{"CC6.7"}, CISv8: []string{"3.10"}, NISTCSF: []string{"PR.DS-02"}})))
	}
	return out
}

// --- helpers (mirror internal/operate) ---

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, c *types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "sspm", Severity: sev,
		Title: title, Endpoint: endpoint, Description: desc,
		Compliance: c, DiscoveredAt: now,
		// grounded by a deterministic config fact, not a re-fired exploit:
		VerificationStatus: types.VerificationVerified,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }

func roleLabel(role string) string {
	if role == "admin" {
		return "owner"
	}
	return "member"
}

func joinNames(names []string) string {
	if len(names) > 8 {
		names = append(names[:8:8], "…")
	}
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
