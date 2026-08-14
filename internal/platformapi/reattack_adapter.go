package platformapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// reattack_adapter.go supplies the runner's Reattacker: it resolves finding keys back to findings and
// re-runs their exploits, turning "the scanner no longer sees it" into "the exploit no longer works".
//
// # A re-attack is active exploitation, and is gated like it
//
// This fires a real payload at a customer's running system, on a schedule, without anyone clicking
// anything. That is a materially different act from reading a catalog or diffing a scan, so it carries
// the same gates the pentest flow uses rather than a weaker set of its own:
//
//   - THE OPERATOR MUST HAVE ENABLED LIVE PROBING. Without a wired Prober (TSENGINE_ACTIVE_EXPLOIT)
//     nothing here runs, and the verdicts come back unverified rather than absent.
//   - THE TENANT MUST HAVE PROVEN OWNERSHIP of the target. A finding on an unverified asset is NEVER
//     re-attacked. Verifying a fix is not a reason to send payloads at a host nobody proved they own,
//     and "we were only checking" is not a defence.
//
// Both gates fail CLOSED and fail HONESTLY: a skipped finding comes back Verified=false, which
// retest.ApplyReattack treats as "changes nothing" rather than as "not exploitable". A gate that
// silently produced a clean verdict would be worse than having no gate at all.

// ReattackVerdicts is the runner.Service.Reattacker implementation.
//
// Returns a verdict per key. Keys we could not or would not re-test come back unverified, so the
// caller's rescan verdict stands untouched.
func (d Deps) ReattackVerdicts(ctx context.Context, tenantID string, keys []string) map[string]retest.ReattackVerdict {
	if len(keys) == 0 || d.Store == nil {
		return nil
	}
	out := make(map[string]retest.ReattackVerdict, len(keys))

	// GATE 1: live probing must be enabled by the operator.
	//
	// REDUNDANT ON PURPOSE. pentest.Reattack independently refuses a nil prober, so removing this
	// early-out changes nothing observable — a mutation test confirmed that. It stays because it
	// avoids the store reads and the ownership lookup when nothing can run, and because a safety
	// property worth having is worth having at both layers rather than relying on a callee to keep
	// its refusal forever.
	if d.Prober == nil {
		for _, k := range keys {
			out[k] = retest.ReattackVerdict{Verified: false,
				Evidence: "Live re-testing is not enabled in this deployment, so the exploit was not re-run."}
		}
		return out
	}

	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil // a store error is not a verdict; leave every rescan result alone
	}
	owned, err := d.ownedTargets(ctx, tenantID)
	if err != nil {
		return nil
	}

	// Resolve keys → findings. The finding may be ABSENT from the latest scan (that is the whole
	// point — a working fix makes it absent), so this reads the stored set rather than a fresh one.
	byKey := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byKey[detect.Key(f)] = f
	}

	var toProbe []types.Finding
	var probeKeys []string
	for _, k := range keys {
		f, ok := byKey[k]
		if !ok {
			out[k] = retest.ReattackVerdict{Verified: false,
				Evidence: "The original finding is no longer on record, so its exploit could not be rebuilt."}
			continue
		}
		// GATE 2: ownership. Never send a payload at a host the tenant has not proven they control.
		if !ownsEndpoint(f.Endpoint, owned) {
			out[k] = retest.ReattackVerdict{Verified: false,
				Evidence: "This target is not ownership-verified, so we did not re-run the exploit against it. " +
					"Verify ownership to enable re-attack confirmation."}
			continue
		}
		toProbe = append(toProbe, f)
		probeKeys = append(probeKeys, k)
	}
	if len(toProbe) == 0 {
		return out
	}

	results := pentest.Reattack(ctx, toProbe, d.Prober,
		func(i int) string { return fmt.Sprintf("tsrt%s%04d", shortID(tenantID), i) }, nil)

	for i, r := range results {
		if i >= len(probeKeys) {
			break // defensive: Reattack returns one result per finding, but never index past our keys
		}
		out[probeKeys[i]] = retest.ReattackVerdict{
			Exploitable: r.Status == pentest.StillExploitable,
			// Only a probe that actually RAN counts as verified. Unverifiable must never be mistaken
			// for "not exploitable" — that is the false all-clear the whole chain refuses.
			Verified: r.Status == pentest.StillExploitable || r.Status == pentest.ClosedWithProof,
			Evidence: r.Evidence,
		}
	}
	return out
}

// ownsEndpoint reports whether an endpoint belongs to a target the tenant proved they control.
// Literal containment, the same attribution rule the data-tier and per-asset compliance views use —
// and it fails closed: no match means no re-attack.
func ownsEndpoint(endpoint string, owned []string) bool {
	if endpoint == "" {
		return false
	}
	for _, t := range owned {
		if t != "" && strings.Contains(endpoint, t) {
			return true
		}
	}
	return false
}

// shortID gives the canary a per-tenant prefix so a probe observed in a customer's logs is
// attributable to their own account and not confusable with another tenant's.
func shortID(tenantID string) string {
	if len(tenantID) > 4 {
		return tenantID[:4]
	}
	return tenantID
}
