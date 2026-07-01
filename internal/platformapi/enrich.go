package platformapi

import (
	"os"

	"github.com/ClatTribe/tsengine/internal/tracer"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// enrichFindings runs the L1.5 host-side enrichment chain over a batch of PLATFORM-NATIVE findings before
// they are stored — the SAME hooks the engine's sandbox tracer runs (§11): fp_filter, service_eol,
// surface_priority, exploitability, threat_intel (CVSS/KEV/EPSS), compliance-crosswalk, and the finalize
// pass (corroboration, cross-tool merge, confidence). Engine-scanned findings (repo/container/web/cloud)
// already get this via the sandbox tracer; findings that enter through the platform's OWN ingest paths
// (identity, OSINT, SaaS posture, TPRM, device, cloud-drift/CDR, TLS) previously called PutFinding
// directly and landed UN-enriched — no threat-intel, no exploitability, no confidence, and any CVE they
// carried never got KEV/EPSS. This closes that asymmetry so a finding is enriched the same way no matter
// which door it came in.
//
// Safe for these classes: the compliance hook MERGES (never clobbers) the inline mapping each detector
// already set (compliance.go), and threat_intel/service_eol/exploitability are no-ops without a
// CVE/product/critical-CWE — so a config/posture finding keeps its inline compliance and simply gains
// corroboration + confidence, while a CVE-bearing one (e.g. a cloud-drift or OSINT advisory) also gains
// KEV/EPSS. Honors TSENGINE_L15_DISABLED (the ablation flag) — then enriched == input.
func enrichFindings(findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}
	tr := tracer.New(os.Getenv("TSENGINE_L15_DISABLED") == "1", hooks.DefaultPerFinding(), hooks.DefaultFinalize())
	for _, f := range findings {
		tr.Add(f)
	}
	tr.Finalize()
	return tr.Enriched()
}
