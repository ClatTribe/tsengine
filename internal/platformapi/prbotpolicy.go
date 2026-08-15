package platformapi

import (
	"context"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// prbotpolicy.go: one answer to "is the PR merge gate on, and at what severity?".
//
// THE BUG THIS EXISTS TO PREVENT. The settings endpoint and the CI gate each decided for themselves
// what an UNCONFIGURED tenant meant, and they disagreed:
//
//	GET  /v1/settings/pr-bot   →  {"enabled": false}     (nil policy → off)
//	POST /v1/ci/pr-check       →  enabled := true        (nil policy → ON, blocks the merge)
//
// So a workspace that had never touched the setting — which is every new workspace — read "PR bot:
// disabled" in Settings, wired up the GitHub Action, and had its merges blocked by a feature the
// product told them was off. Explicitly disabling it fixed the behaviour, which made the bug look
// like a fluke rather than a default.
//
// A MERGE GATE MUST FAIL OPEN. Surprising permissiveness costs a customer one unblocked PR they can
// re-check; surprising enforcement blocks a team's deploys on a policy they never chose, at the worst
// possible moment, from a vendor they just installed. And the customer has already opted into RUNNING
// the check by adding it to CI — the only question here is whether it blocks, and Settings says no.
type prBotPolicy struct {
	Enabled bool
	BlockAt types.Severity
}

// resolvePRBotPolicy returns the effective policy for a tenant. Both the settings view and the CI
// gate read it, so the two cannot drift into disagreeing again.
//
// Unconfigured, or unreadable, means OFF: the gate stays informational until someone turns it on.
func (d Deps) resolvePRBotPolicy(ctx context.Context, tenantID string) prBotPolicy {
	p := prBotPolicy{Enabled: false, BlockAt: types.SeverityHigh}
	if d.Store == nil {
		return p
	}
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || t.PRBot == nil {
		return p
	}
	p.Enabled = t.PRBot.Enabled
	if t.PRBot.BlockSeverity != "" {
		p.BlockAt = types.Severity(t.PRBot.BlockSeverity)
	}
	return p
}
