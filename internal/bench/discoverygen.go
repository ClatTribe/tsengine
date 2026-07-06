package bench

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// discoverygen.go is the END-TO-END bridge for the impact-discovery benchmark: it derives a DiscoveryScenario
// from REAL scanner findings by running the actual product substrate (`crossdetect.Correlate`), instead of a
// hand-authored estate. This closes the honesty loop — the whole shipped finding path is exercised:
//
//	real scanner findings → crossdetect.Correlate (the FACTS: which findings chain to a crown jewel)
//	  → EstateFromFindings (build the estate + GROUND TRUTH from the engine's chains)
//	  → the LLM engineer reasons over the raw findings (the JUDGMENT)
//	  → ScoreDiscovery (recall/precision vs the engine-derived truth).
//
// The ground truth is NOT hand-labelled: a finding is high-impact iff the deterministic substrate places it on
// a chain reaching a crown jewel (§10 — the engine, not a human, decides what reaches impact). So the LLM's
// job is to independently identify, from the same raw findings the engine saw, the cross-surface chain the
// substrate surfaced — and to leave the non-chaining noise alone. This measures the PRODUCT, not a model
// given invented facts.

// ScanInput is a realistic multi-scanner scan: the asset inventory + the flat finding list (the shape the
// engine consumes). It is what a real tsengine scan emits before enrichment.
type ScanInput struct {
	Assets   []platform.Asset `json:"assets"`
	Findings []types.Finding  `json:"findings"`
}

// EstateFromFindings runs the real substrate over a scan and returns a discovery estate whose ground-truth
// high-impact set is exactly the findings the engine chained to a crown jewel. Context lists the asset
// inventory only (never the chains — the engineer must re-derive the linkage from the raw findings, as the
// engine did). Returns the scenario + the chains the substrate found (for reporting/self-check).
func EstateFromFindings(id string, in ScanInput) (DiscoveryScenario, []correlate.Chain) {
	chains := crossdetect.Correlate(in.Assets, in.Findings)

	// ground truth: a finding is high-impact iff it sits on a chain to a crown jewel. Capture, per finding,
	// the crown step's nature so we can classify the impact category the same way a human would read it.
	inChain := map[string]bool{}
	crownTitleFor := map[string]string{}
	for _, ch := range chains {
		if len(ch.Steps) == 0 || !ch.Steps[len(ch.Steps)-1].CrownJewel {
			continue // only chains that actually terminate at a crown jewel count
		}
		crown := ch.Steps[len(ch.Steps)-1]
		for _, s := range ch.Steps {
			inChain[s.FindingID] = true
			crownTitleFor[s.FindingID] = crown.Title
		}
	}

	// surface per finding, via the same classifier the engine uses (crossdetect.Assets).
	surfaceOf := map[string]string{}
	for _, a := range crossdetect.Assets(in.Assets, in.Findings) {
		for _, f := range a.Findings {
			surfaceOf[f.ID] = a.Type
		}
	}

	sc := DiscoveryScenario{ID: id, Name: "End-to-end: estate derived from real scanner findings via crossdetect"}
	for _, a := range in.Assets {
		sc.Context = append(sc.Context, "Asset: "+a.Type+" — "+a.Target)
	}
	for _, f := range in.Findings {
		df := DiscoveryFinding{
			ID: f.ID, Surface: surfaceOf[f.ID], Severity: f.Severity,
			Title: firstNonEmptyStr(f.Title, f.RuleID), Detail: f.Description,
		}
		if inChain[f.ID] {
			df.HighImpact = true
			df.ImpactType = classifyCrown(crownTitleFor[f.ID])
			df.Reaches = crownTitleFor[f.ID]
		}
		sc.Findings = append(sc.Findings, df)
	}
	sort.SliceStable(sc.Findings, func(i, j int) bool { return sc.Findings[i].ID < sc.Findings[j].ID })
	return sc, chains
}

// classifyCrown maps a crown-jewel step's title to the impact category a human would name.
func classifyCrown(title string) ImpactType {
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "pii") || strings.Contains(t, "customer") || strings.Contains(t, "data") ||
		strings.Contains(t, "secret") || strings.Contains(t, "backup"):
		return ImpactDataExposure
	case strings.Contains(t, "admin") || strings.Contains(t, "privilege") || strings.Contains(t, "privesc") ||
		strings.Contains(t, "*:*") || strings.Contains(t, "root"):
		return ImpactPrivEsc
	default:
		return ImpactLateral // a cross-surface chain to a crown jewel of unspecified kind
	}
}

func firstNonEmptyStr(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
