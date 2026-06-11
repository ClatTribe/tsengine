package remediate

import (
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// proposeIdentity turns an operate (workspace) identity/email finding into a SPECIFIC,
// copy-pasteable remediation ticket — a runbook a non-technical owner can execute in
// minutes, not a generic "review this". Operate cites the offending entity (user /
// domain / app) in the finding's Endpoint, so the runbook names exactly what to fix.
//
// These stay file_ticket / tier 1: a ticket is reversible + informational, so it
// auto-delivers (the actual identity mutation — enforce MFA, revoke a grant — has no live
// write path yet; the connector Apply is a documented stub pending admin creds). The
// structured `remediation_type` + `target` are carried so a future live Apply has the
// machine-readable fix ready. Returns false for any non-identity rule so Propose falls
// back to the generic ticket.
func proposeIdentity(f types.Finding, asset platform.Asset, idgen func() string) (platform.Action, bool) {
	target := nz(f.Endpoint, asset.Target) // the cited user / domain / app
	r, ok := identityRunbook(f.RuleID, target)
	if !ok {
		return platform.Action{}, false
	}
	return platform.Action{
		ID: id("act", idgen), TenantID: asset.TenantID, FindingID: f.ID, ConnectionID: asset.ConnectionID,
		Kind: platform.ActFileTicket, Tier: 1, Status: platform.ActProposed,
		Title: "tsengine: " + r.title,
		Payload: map[string]any{
			"summary":          r.body + "\n\n— cites finding " + f.ID + " (" + string(f.Severity) + ")",
			"remediation_type": r.kind,
			"target":           target,
		},
	}, true
}

type runbook struct {
	title string
	kind  string // machine-readable remediation type (for a future live Apply)
	body  string // the human runbook
}

// identityRunbook is the per-rule remediation. DNS-level fixes (DMARC/SPF) are concrete
// and provider-neutral (the exact record); console actions are stated provider-neutrally
// because the security action is identical across Google/M365/Okta — only the menu path
// differs, and naming the wrong provider's path would mislead.
func identityRunbook(ruleID, target string) (runbook, bool) {
	switch ruleID {
	case "operate::admin-without-mfa":
		return runbook{"enforce MFA for admin " + target, "mfa_enforce",
			"Require MFA / 2-step verification for the administrator " + target + " immediately, then review their recent activity. An admin without MFA is the highest-value account-takeover target."}, true
	case "operate::user-without-mfa":
		return runbook{"enforce MFA for " + target, "mfa_enforce",
			"Require MFA for " + target + ", and turn on org-wide MFA enforcement so every new account inherits it."}, true
	case "operate::dmarc-not-enforced":
		return runbook{"enforce DMARC for " + target, "dmarc_publish",
			"Publish an enforcing DMARC policy for " + target + ". Once SPF and DKIM pass, set the `_dmarc." + target + "` TXT record to:\n\n    v=DMARC1; p=reject; rua=mailto:dmarc@" + target + "\n\nIf you need a monitoring window first, start at `p=quarantine`, then move to `p=reject`."}, true
	case "operate::spf-dkim-missing":
		return runbook{"publish SPF/DKIM for " + target, "email_auth_publish",
			"Publish SPF and enable DKIM for " + target + " — both are prerequisites for DMARC. Add an SPF TXT record (`v=spf1 include:<your-mail-provider> -all`), enable DKIM signing in your mail provider, then publish its DKIM selector record."}, true
	case "operate::oauth-admin-scope":
		return runbook{"revoke admin-scoped app " + target, "oauth_revoke",
			"Review and revoke the third-party app " + target + ": it holds a directory/admin scope and is effectively shadow-admin. Remove the grant in your identity provider's third-party-app admin unless it is explicitly sanctioned."}, true
	case "operate::oauth-unverified-app":
		return runbook{"review unverified app " + target, "oauth_review",
			"Confirm the unverified third-party app " + target + " is sanctioned; revoke its grant if it is not."}, true
	case "operate::stale-account":
		return runbook{"suspend stale account " + target, "account_suspend",
			"Suspend or deprovision the stale account " + target + " — it has been idle past your threshold and is a quiet attack surface."}, true
	case "operate::excess-super-admins":
		return runbook{"reduce super-admins", "reduce_admins",
			"Reduce super-administrators to the minimum. Downgrade non-essential super-admins to scoped admin roles."}, true
	default:
		return runbook{}, false
	}
}
