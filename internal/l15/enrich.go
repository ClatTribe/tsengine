// Package l15 runs the L1.5 host-side enrichment chain over a batch of findings.
//
// It exists as its own package because BOTH doors into the findings store need it and neither can
// import the other: internal/platformapi imports internal/runner, so the runner cannot reach back
// into platformapi, and the chain cannot live in internal/tracer because internal/tracer/hooks
// already imports tracer (a cycle). One implementation, both callers.
package l15

import (
	"os"

	"github.com/ClatTribe/tsengine/internal/tracer"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Enrich runs the L1.5 chain (§11) over a batch of findings before they are stored: fp_filter,
// service_eol, surface_priority, exploitability, threat_intel (CVSS/KEV/EPSS), the compliance
// crosswalk, and the finalize pass (corroboration, cross-tool merge, confidence).
//
// WHY THIS IS SHARED RATHER THAN PER-DOOR. The chain was previously a private helper in
// platformapi, whose doc asserted that "engine-scanned findings already get this via the sandbox
// tracer". They do not. The CLI (cmd/tsengine) builds a tracer and runs the hooks; the PLATFORM's
// engine path does not — runner.scanAsset takes what the scanner returns and calls PutFinding
// directly, and no tracer exists anywhere in internal/orchestrator or internal/sandbox. So the
// product's PRIMARY path — every repo, container, web, api and ip scan — stored findings with no
// KEV/EPSS, no exploitability, no FP filtering, no compliance mapping and no confidence, while the
// secondary ingest paths were fully enriched. The asymmetry ran the opposite way to the one the
// comments described.
//
// That is not cosmetic for the audience this serves: a security engineer prioritises by
// exploited-in-the-wild (KEV) and patch-priority (EPSS), and triages by confidence. Findings
// missing all three are the raw scanner noise practitioners say costs more than it saves.
//
// Safe across finding classes: the compliance hook MERGES rather than clobbers any inline mapping a
// detector already set, and threat_intel/service_eol/exploitability no-op without a CVE / product
// version / critical CWE. So a config-posture finding keeps its inline compliance and gains
// corroboration + confidence, while a CVE-bearing one also gains KEV/EPSS.
//
// Honors TSENGINE_L15_DISABLED (the §14.1 ablation flag) — then Enrich is the identity function,
// which is what makes the L1-vs-L1.5 delta measurable.
func Enrich(findings []types.Finding) []types.Finding { return EnrichDetailed(findings).Enriched }

// Result is the enrichment outcome plus the trail of what the chain CHANGED.
type Result struct {
	// Enriched is the post-chain finding set — what the customer sees.
	Enriched []types.Finding
	// Audit is every demotion, dismissal and merge the chain performed, with the rule and reason
	// (§2.5: L1.5 decisions must be "logged + recoverable" so the security engineer can audit them).
	//
	// This is the half that cannot be reconstructed from Enriched. A surviving finding still carries
	// its own RawOutput and ToolArgs, so what the tool said is recoverable — but a finding the FP
	// filter DROPPED is invisible, and one it demoted shows only its new severity. Without the trail
	// the engineer cannot see what the AI decided not to show them, which is precisely the thing
	// practitioners say they must be able to check before they will trust the output.
	Audit []types.AuditEntry
}

// EnrichDetailed runs the chain and returns the audit trail alongside the enriched findings.
func EnrichDetailed(findings []types.Finding) Result {
	if len(findings) == 0 {
		return Result{Enriched: findings}
	}
	tr := tracer.New(os.Getenv("TSENGINE_L15_DISABLED") == "1", hooks.DefaultPerFinding(), hooks.DefaultFinalize())
	for _, f := range findings {
		tr.Add(f)
	}
	tr.Finalize()
	return Result{Enriched: tr.Enriched(), Audit: tr.AuditLog()}
}
