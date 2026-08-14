package platformapi

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/explain"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// explain_issues.go attaches a plain-English explanation to every issue the API returns.
//
// The explain package is useless until a customer reads its output, so this is the half that actually
// closes the readability gap: /v1/issues stops being a list of rule ids and becomes a list of sentences
// a founder can act on.
//
// BLAST RADIUS COMES FROM THE CHAINS ALREADY COMPUTED HERE. handleIssues already calls
// crossdetect.Correlate for the live-risk lens, and a chain's steps carry CrownJewel — the grounded
// answer to "what does this reach". Deriving Reaches from those chains means the blast radius is real
// today, without waiting for a customer to post a cloud inventory. Where no chain covers an issue, the
// explanation says the reach is untraced rather than inventing one (§10).
//
// READ-TIME AND NEVER PERSISTED, like annotateSLA / annotateOnset / annotateBlastRadius. The wording
// improves as the class table and the graph improve; a frozen copy in the store would go stale and
// diverge from what the same finding renders elsewhere.

// annotateExplanations returns one explanation per issue, keyed by issue key.
//
// Deterministic and model-free: this is what makes the AI-off tier readable rather than raw.
func annotateExplanations(issues []crossdetect.Issue, findings []types.Finding, assets []platform.Asset, chains []correlate.Chain) map[string]explain.Explanation {
	if len(issues) == 0 {
		return nil
	}
	byID := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	reach := crownsByFinding(chains)
	labels := assetLabels(assets)

	out := make(map[string]explain.Explanation, len(issues))
	for _, iss := range issues {
		f := representative(iss, byID)
		var reaches []string
		traced := len(chains) > 0 // the correlation ran at all
		for _, id := range iss.FindingIDs {
			reaches = append(reaches, reach[id]...)
		}
		out[iss.Key] = explain.Explain(f, explain.Context{
			Reaches:     dedupeStrings(reaches),
			ReachTraced: traced,
			UnderAttack: iss.Attacked,
			AssetLabel:  labelFor(iss.Endpoint, labels),
		})
	}
	return out
}

// representative picks the finding an issue is best explained by: the first of its rolled-up findings
// we can actually resolve. An issue whose findings are all missing from the store still gets an
// explanation built from the issue's own fields — degraded, but never blank.
func representative(iss crossdetect.Issue, byID map[string]types.Finding) types.Finding {
	for _, id := range iss.FindingIDs {
		if f, ok := byID[id]; ok {
			return f
		}
	}
	return types.Finding{
		ID: iss.Key, RuleID: iss.Key, Title: iss.Title,
		Severity: types.Severity(iss.Severity), Endpoint: iss.Endpoint,
	}
}

// crownsByFinding maps each finding id to the crown jewels its chains reach.
//
// Grounded: a crown is only recorded for findings that appear BEFORE it in the same chain — i.e. the
// step actually leads there. A finding that IS the crown does not "reach" itself, and steps after it
// are not consequences of it.
func crownsByFinding(chains []correlate.Chain) map[string][]string {
	out := map[string][]string{}
	for _, c := range chains {
		for i, s := range c.Steps {
			if !s.CrownJewel {
				continue
			}
			crown := crownLabel(s)
			for _, earlier := range c.Steps[:i] {
				if earlier.FindingID != "" {
					out[earlier.FindingID] = append(out[earlier.FindingID], crown)
				}
			}
		}
	}
	return out
}

// crownLabel names the crown jewel in the customer's terms, not ours.
func crownLabel(s correlate.Step) string {
	switch s.AssetType {
	case "cloud_account":
		return "your cloud account"
	case "repository":
		return "your source code"
	case "domain", "web_application", "api":
		if t := strings.TrimSpace(s.AssetTarget); t != "" {
			return t
		}
		return "your application"
	}
	if t := strings.TrimSpace(s.AssetTarget); t != "" {
		return t
	}
	return "a sensitive system"
}

// assetLabels maps a target string to what the customer calls it, longest-first so the most specific
// asset wins (the same attribution rule the data-tier and per-asset compliance views use).
func assetLabels(assets []platform.Asset) []platform.Asset {
	out := append([]platform.Asset(nil), assets...)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if len(out[j].Target) > len(out[i].Target) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// labelFor finds the asset an endpoint belongs to by literal containment (longest wins). No match →
// empty, and the explanation falls back to "your app" rather than naming the wrong system.
func labelFor(endpoint string, assets []platform.Asset) string {
	if endpoint == "" {
		return ""
	}
	for _, a := range assets {
		if a.Target != "" && strings.Contains(endpoint, a.Target) {
			return a.Target
		}
	}
	return ""
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
