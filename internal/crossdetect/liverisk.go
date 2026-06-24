package crossdetect

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
)

// liverisk.go is the "live / reachable / exploitable" fusion — the central capability of the ACSP
// (Agentic Cloud Security Platform) thesis: "distinguish theoretical from active, reachable,
// exploitable risk." The platform already computes the inputs separately — runtime-attacked
// (AnnotateRuntime), attack-path membership (correlate.Correlate), exposure markers, severity,
// corroboration. This fuses them into ONE grounded verdict per issue so the few that are genuinely
// LIVE float to the top of the noise ("the 5 that matter, not the 500").
//
// Grounded (§10): Live is set only on real signals — an observed attack, a real cross-surface chain
// to a crown jewel, or a concrete exposure marker on a serious corroborated issue. It is a
// PRIORITIZATION lens (platform layer, like data-tier) — it never blocks (§13) and never touches the
// engine's surface_priority (§18.2 inv. 1).

// exposureMarkers are concrete tokens that indicate an issue is reachable from the internet /
// unauthenticated. Kept conservative — each is a real, defensible exposure signal, not a guess.
var exposureMarkers = []string{
	"public", "publicly", "internet", "0.0.0.0/0", "::/0", "anonymous",
	"unauthenticated", "world-readable", "exposed", "open to the internet",
}

// isExposed reports whether an issue carries an internet-exposure signal: an http(s) endpoint (a
// web/api surface is internet-facing by nature) or an exposure marker in its title/key/endpoint.
func isExposed(i Issue) bool {
	ep := strings.ToLower(i.Endpoint)
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return true
	}
	hay := strings.ToLower(i.Title + " " + i.Key + " " + i.Endpoint)
	for _, m := range exposureMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// AnnotateLiveRisk fuses the runtime/exposure/reachability signals into each issue's Live verdict and
// returns the count of live issues. chains are the cross-surface attack paths (crossdetect.Correlate
// output) — an issue is "on an attack path" when any of its rolled-up findings is a step in a chain.
// Idempotent + grounded: an issue goes Live only on a real signal.
func AnnotateLiveRisk(issues []Issue, chains []correlate.Chain) int {
	// finding-ids that appear as a step in any attack chain (reachability).
	inChain := map[string]bool{}
	for _, ch := range chains {
		for _, st := range ch.Steps {
			if st.FindingID != "" {
				inChain[st.FindingID] = true
			}
		}
	}

	live := 0
	for i := range issues {
		exposed := isExposed(issues[i])
		onPath := false
		for _, fid := range issues[i].FindingIDs {
			if inChain[fid] {
				onPath = true
				break
			}
		}
		issues[i].Exposed = exposed
		issues[i].InAttackPath = onPath

		reason := ""
		switch {
		case issues[i].Attacked:
			reason = "under active attack in production"
		case exposed && onPath:
			reason = "internet-exposed and on an attack path to a crown jewel"
		case exposed && sevRank(issues[i].Severity) >= sevRank("high") && issues[i].Confirmed:
			reason = "internet-exposed, high-severity, and corroborated by multiple tools"
		}
		if reason != "" {
			issues[i].Live = true
			issues[i].LiveReason = reason
			live++
		}
	}
	return live
}
