package l2

import (
	"context"

	"github.com/ClatTribe/tsengine/pkg/types"
)

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

	// CloudInvestigator, when set, lets the L2 GENERALIST delegate a cloud-depth question to the cloud
	// SPECIALIST (cloudagent over the tenant's stored cloud snapshot) — the framework's altitude split:
	// the generalist reasons over the whole estate and dispatches into deep cloud-graph reasoning (IAM,
	// reachability, privesc, attack paths) on demand. It's a NEUTRAL func so l2 stays engine-pure (never
	// imports cloudagent/cloudsnap/the platform); the platform injects the closure. nil → the
	// investigate_cloud tool is not exposed (so the ≤12-tool cap is never spent on a dead tool).
	CloudInvestigator func(ctx context.Context, focus string) (string, error)

	// CodeInvestigator is the CODE twin of CloudInvestigator: it lets the generalist delegate a code
	// finding to the code-depth SPECIALIST (codeagent — opens the source, traces taint to a sink,
	// computes a secret's blast radius, finds the right-layer fix). Same neutral-func discipline (l2 never
	// imports codeagent); the platform injects the closure and only when source is reachable (a connected
	// repo), so nil → the investigate_code tool is not exposed and the ≤12-tool cap is never spent on it.
	CodeInvestigator func(ctx context.Context, focus string) (string, error)

	// Engineer is the ACTING half of the tool belt (search the estate, propose a fix, request proof,
	// check a fix, file a ticket), injected by the platform because it needs the store and the HITL
	// desk. Empty → the Lead keeps its read-only catalog and the ≤12 cap is not spent on tools that
	// cannot act.
	Engineer Catalog
}

// BuildCatalog assembles the per-asset L2 catalog from Deps. The catalog is
// uniform across assets for the translator L2 — the tools are
// asset-agnostic (read findings, threat-intel, compliance, probe, report),
// unlike strix's per-asset specialist tools (those are L1/escalation). The
// ≤12 cap is therefore trivially met (~10). Validate() enforces it.
func BuildCatalog(d Deps) Catalog {
	c := CoreTools()
	c = append(c, readTools(d)...)     // L2-1: get_finding
	c = append(c, reportTools(d)...)   // L2-2: create/update report + record_hypothesis
	c = append(c, externalTools(d)...) // L2-3: threat-intel / compliance / probe / send_request
	c = append(c, d.engineerTools()...)
	return c
}

// engineerTools adds the ACTING half of the belt — the tools that let the Lead change something
// rather than only describe it. Without them every catalog tool is read-only or writes to our own
// store, which is what makes the agent an analyst instead of an engineer.
//
// They are PHASE-SCOPED, and that is not cosmetic. The ≤12 cap (§2.6) counts what the model sees at
// any ONE moment, and bolting five tools onto an eleven-tool catalog would blow it. Past ~12, tool-use
// accuracy degrades steeply — so an unscoped belt would make the agent WORSE at the job it just gained
// the ability to do. Scoping each tool to the phase where it is actually useful keeps every phase
// inside the cap while still giving the agent hands:
//
//	triage       what am I dealing with · did my last fix hold
//	investigate  settle a doubt with an exploit attempt
//	report       commit: propose the fix, or hand off what is not ours
func (d Deps) engineerTools() Catalog {
	if len(d.Engineer) == 0 {
		return nil // not wired → the cap is never spent on tools that cannot act
	}
	phases := map[string][]Phase{
		"search_estate":    {PhaseTriage, PhaseInvestigate},
		"check_fix_status": {PhaseTriage},
		"request_proof":    {PhaseInvestigate},
		"propose_fix":      {PhaseReport},
		"open_ticket":      {PhaseReport},
	}
	out := make(Catalog, 0, len(d.Engineer))
	for _, t := range d.Engineer {
		if p, ok := phases[t.Schema.Name]; ok {
			t.Phases = p
		}
		out = append(out, t)
	}
	return out
}
