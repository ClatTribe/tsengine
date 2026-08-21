package operate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// coverage.go declares what an identity posture scan could NOT check.
//
// It emits findings under the shared `coverage::` namespace (asset.CoverageRulePrefix —
// spelled literally here because operate is a ScanRunner rather than an asset.Handler and
// must not import the asset package). Downstream that buys the whole contract for free:
// internal/coverage surfaces them as declared gaps and keeps them out of the asset's
// finding count, and crossdetect keeps them out of the issues list.
//
// WHY IDENTITY NEEDS THIS MOST. The grant read is best-effort on every provider: it wants
// a scope beyond what onboarding asks for, and when it is missing the fetcher degrades to
// no grants rather than failing. So the single most valuable finding here — a third-party
// app holding admin scope, which is a shadow administrator nobody provisioned — silently
// becomes a clean OAuth posture. The customer is not told they are missing a permission;
// they are told they have no risky apps.
const coverageRulePrefix = "coverage::"

// gapCheck describes one thing that could not be checked, and what to do about it.
type gapCheck struct {
	key      string
	title    string
	whatFor  string // what this check would have found
	remedy   string // how the customer restores it
	provider bool   // true = a provider limit (not fixable by granting a scope)
}

var unavailableChecks = map[string]gapCheck{
	"oauth_grants": {
		key:   "oauth_grants",
		title: "Third-party OAuth grants could not be read",
		whatFor: "apps holding admin scope on your workspace — a third-party application with " +
			"directory-write access is an administrator nobody provisioned, and it survives every " +
			"password reset and offboarding step",
		remedy: "grant the API scope for reading OAuth tokens / service principals, or post a " +
			"workspace snapshot that includes them",
	},
	"mfa": {
		key:     "mfa",
		title:   "Multi-factor enrolment could not be read",
		whatFor: "accounts — especially administrators — signing in with a password alone",
		remedy:  "grant the authentication-methods read scope, or post a snapshot including per-user MFA",
	},
	"users": {
		key:     "users",
		title:   "The user directory could not be read",
		whatFor: "stale accounts, over-privileged admins and incomplete offboarding",
		remedy:  "grant the directory read scope, or post a workspace snapshot",
	},
}

var providerLimitChecks = map[string]gapCheck{
	"oauth_publisher_verification": {
		key:      "oauth_publisher_verification",
		title:    "App publisher verification is not available from this provider",
		whatFor:  "third-party apps from unverified publishers",
		remedy:   "review the connected apps in the admin console directly — this provider's API does not expose publisher status, so no scope will restore it",
		provider: true,
	},
}

// CoverageGaps returns the informational disclosures for a workspace's unavailable checks.
//
// Grounded (§10): it reports only what the FETCHER recorded as unreadable. It never infers
// a gap from an empty result, because an empty result is exactly the ambiguity this exists
// to resolve — inferring would make a genuinely clean workspace produce a gap for every
// check that found nothing.
//
// Severity is informational by construction. A check that did not run has no evidence for
// one, and a high on an unread OAuth grant is the same overclaim as a clean bill of health,
// pointed the other way.
func CoverageGaps(ws Workspace, now time.Time) []types.Finding {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	target := ws.Provider + ":" + ws.Org

	type pending struct {
		gc   gapCheck
		kind string
	}
	var todo []pending
	for _, k := range dedupeSorted(ws.Unavailable) {
		if gc, ok := unavailableChecks[k]; ok {
			todo = append(todo, pending{gc, "unavailable"})
		}
	}
	// ProviderLimits are DELIBERATELY NOT emitted as per-scan findings.
	//
	// A provider limit is standing: identical on every scan of every Google workspace,
	// forever, and unchanged by anything the customer does. Emitting it per scan makes an
	// unchanging sentence arrive as new information every time, which is how a disclosure
	// becomes the thing people learn to scroll past — and then the one that MATTERS,
	// sitting beside it, gets scrolled past too.
	//
	// This is the same line internal/coverage draws between DeclaredGaps (what THIS run
	// hit) and UntestedClasses (what this asset TYPE cannot reach). The field is kept
	// because the fact is real and worth carrying; it belongs on a standing capability
	// surface rather than in a finding stream, and that surface is the follow-on.
	_ = providerLimitChecks
	if len(todo) == 0 {
		return nil
	}

	out := make([]types.Finding, 0, len(todo))
	for i, p := range todo {
		lead := "This check did not run, so nothing here says your workspace is clean on it."
		if p.gc.provider {
			lead = "This provider cannot answer this check at all, so no scan of it can clear this."
		}
		desc := fmt.Sprintf("%s\n\nIt would have found: %s.\n\nTo restore it: %s.\n\n"+
			"This is a coverage gap, not a finding — it reports an absence of testing, not a problem "+
			"we observed.", lead, p.gc.whatFor, p.gc.remedy)
		out = append(out, types.Finding{
			ID:           fmt.Sprintf("identity-gap-%03d", i+1),
			RuleID:       coverageRulePrefix + "identity-" + strings.ReplaceAll(p.gc.key, "_", "-"),
			Tool:         "coverage",
			Severity:     types.SeverityInfo,
			Endpoint:     target,
			Title:        p.gc.title,
			Description:  desc,
			ToolArgs:     map[string]string{"provider": ws.Provider, "check": p.gc.key, "kind": p.kind},
			DiscoveredAt: now,
		})
	}
	return out
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
