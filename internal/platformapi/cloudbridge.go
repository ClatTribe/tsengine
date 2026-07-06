package platformapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// cloudBridges (G2) builds grounded CROSS-SURFACE entry-point hints for the AI Cloud Engineer: it runs
// crossdetect correlation over the tenant's estate and extracts the chains that bridge a foothold on
// ANOTHER surface (a code repo, a web app, an exposed host) INTO the cloud account, then formats each as
// a short hint naming the shared entity + the cloud target. The cloud specialist reasons over the cloud
// graph in isolation otherwise (it has no crossdetect awareness) — so without this it cannot know that a
// leaked key in code IS an attacker foothold in this account. This is the code→cloud wedge fed to the
// depth agent.
//
// Grounded (§10): every hint is derived from a real correlation chain over real findings; the agent still
// must confirm each recorded issue in the graph, so a hint only tells it WHERE to look, never authorises
// an ungrounded issue. Best-effort by construction — a nil/empty estate yields no hints. Capped so a noisy
// estate can't blow the prompt.
func cloudBridges(assets []platform.Asset, findings []types.Finding) []string {
	const maxHints = 8
	chains := crossdetect.Correlate(assets, findings)
	seen := map[string]bool{}
	out := make([]string, 0, len(chains))
	for _, ch := range chains {
		hint, ok := bridgeHint(ch)
		if !ok || seen[hint] {
			continue
		}
		seen[hint] = true
		out = append(out, hint)
		if len(out) >= maxHints {
			break
		}
	}
	return out
}

// bridgeHint returns a hint string for a chain IFF it bridges a non-cloud entry surface into a
// cloud_account crown jewel via a shared entity — the code→cloud (or web/host→cloud) footholds the cloud
// depth agent is otherwise blind to. Returns ("", false) for a purely-cloud chain or one with no cloud
// destination (nothing for the cloud specialist to act on).
func bridgeHint(ch correlate.Chain) (string, bool) {
	var entry *correlate.Step // the non-cloud foothold (the first one)
	var cloud *correlate.Step // the cloud crown jewel reached
	var via string
	for i := range ch.Steps {
		s := &ch.Steps[i]
		if s.AssetType == "cloud_account" {
			cloud = s
		} else if entry == nil {
			entry = s
		}
		if s.ViaEntity != "" && via == "" {
			via = s.ViaEntity
		}
	}
	if entry == nil || cloud == nil {
		return "", false // not a cross-surface→cloud chain
	}
	surface := entry.AssetType
	if surface == "" {
		surface = "another surface"
	}
	b := &strings.Builder{}
	if via != "" {
		fmt.Fprintf(b, "shared %s bridges ", via)
	}
	fmt.Fprintf(b, "%s foothold %q → cloud target %q", surface, clip(entry.Title, 80), clip(cloud.Title, 80))
	if cloud.AssetTarget != "" {
		fmt.Fprintf(b, " (%s)", cloud.AssetTarget)
	}
	return b.String(), true
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// tenantCloudBridges is the store-backed convenience: pull the tenant's assets + findings and compute the
// bridges. Best-effort — any store error yields no hints (the agent runs without the cross-surface prior,
// never fails). Used by both the on-demand investigation handler and the L2-delegated cloud investigator.
func (d Deps) tenantCloudBridges(ctx context.Context, tenantID string) []string {
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil
	}
	return cloudBridges(assets, findings)
}
