package remediate

import (
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// proposeIdentity turns an operate (workspace) identity/email finding into a SPECIFIC,
// copy-pasteable remediation — a runbook a non-technical owner can execute in minutes,
// not a generic "review this". Operate cites the offending entity (user / domain / app)
// in the finding's Endpoint, so the remediation names exactly what to fix.
//
// Two shapes, chosen by whether a LIVE connector write path exists for the (remediation,
// provider) pair (liveIdentityMutation):
//
//   - Live path  → a tier-2 ActApplyConfig: the human approves it in the inbox, then the
//     agent applies it through the connector (e.g. Okta suspends the stale account). This
//     is the autonomous-with-approval loop for non-tech identity — the gate (§18.2 inv. 3)
//     still holds; the connector is reached only after a HITL verdict.
//   - No live path → a tier-1 file_ticket runbook (reversible + informational, auto-
//     delivers): the connector Apply is a documented stub, or the fix is a DNS / console
//     action the human performs, so a ticket — not a falsely-confident auto-apply — is the
//     honest artifact. The machine-readable remediation_type + target ride along either
//     way, so the moment that provider's write path lands it promotes with one line.
//
// Returns false for any non-identity rule so Propose falls back to the generic ticket.
func proposeIdentity(f types.Finding, asset platform.Asset, idgen func() string) (platform.Action, bool) {
	target := nz(f.Endpoint, asset.Target) // the cited user / domain / app
	r, ok := identityRunbook(f.RuleID, target)
	if !ok {
		return platform.Action{}, false
	}
	payload := map[string]any{
		"summary":          r.body + "\n\n— cites finding " + f.ID + " (" + string(f.Severity) + ")",
		"remediation_type": r.kind,
		"target":           target,
	}
	act := platform.Action{
		ID: id("act", idgen), TenantID: asset.TenantID, FindingID: f.ID, ConnectionID: asset.ConnectionID,
		Status: platform.ActProposed, Title: "tsengine: " + r.title, Payload: payload,
	}
	if liveIdentityMutation(r.kind, asset.Meta["provider"]) {
		act.Kind, act.Tier = platform.ActApplyConfig, tierApplyConfig // gated mutation
	} else {
		act.Kind, act.Tier = platform.ActFileTicket, 1 // runbook ticket
	}
	return act, true
}

// liveIdentityMutation reports whether an identity remediation has a live, reversible
// connector write path for the asset's provider — making it safe to propose as a
// HITL-gated auto-remediation instead of a runbook ticket. Conservative by design: only the
// reversible account-suspend lifecycle transition promotes, and only for the IdPs whose
// connector.Apply has a live write path — Okta (suspend), Google Workspace (suspend), and
// Microsoft 365 (disable sign-in). Every other (type, provider) stays a ticket until its
// connector Apply lands. Each live path still needs the IdP's write scope (read-only by
// onboarding default); without it the Apply returns the provider's 403 honestly.
func liveIdentityMutation(remediationType, provider string) bool {
	if remediationType != "account_suspend" {
		return false
	}
	switch provider {
	case platform.ConnOkta, platform.ConnGWorkspace, platform.ConnM365:
		return true
	default:
		return false
	}
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
