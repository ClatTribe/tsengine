package l2

import "github.com/ClatTribe/tsengine/pkg/types"

// Deps are the services + inputs the L2 catalog's tool handlers need. It's
// the seam between the agent (pure loop) and the outside world (L1
// findings, threat-intel/compliance corpora, the /replay prober, an HTTP
// client). Production wires real implementations; tests wire mocks — so
// the whole catalog is unit-testable without a sandbox or a network.
//
// Fields are added wave-by-wave: L2-1 needs only the L1 findings; L2-3
// adds ThreatIntel/Compliance/Prober/HTTP.
type Deps struct {
	// Target is the asset under translation (for the system prompt).
	Target types.Asset
	// L1Findings is the enriched L1 input the Lead triages (read via
	// get_finding; the digest rides in the prompt).
	L1Findings []types.Finding

	// --- external services (L2-3) ---
	ThreatIntel ThreatIntelLookup
	Compliance  ComplianceLookup
	Prober      Prober
	HTTP        HTTPDoer
}

// BuildCatalog assembles the per-asset L2 catalog from Deps. The catalog is
// uniform across assets for the translator L2 — the tools are
// asset-agnostic (read findings, threat-intel, compliance, probe, report),
// unlike strix's per-asset specialist tools (those are L1/escalation). The
// ≤12 cap is therefore trivially met (~10). Validate() enforces it.
func BuildCatalog(d Deps) Catalog {
	c := CoreTools()
	c = append(c, readTools(d)...)
	c = append(c, externalTools(d)...) // L2-3 (no-ops if services nil)
	return c
}
