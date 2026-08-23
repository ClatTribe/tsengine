package hooks

import (
	"math"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Confidence is the L1.5 quality-signal hook (strix parity — its #1 triage
// signal). It runs LAST in the finalize chain (after corroborator set
// corroborated_by and cross_tool_merge collapsed duplicates) and stamps every
// enriched finding with:
//
//   - VerificationStatus: pattern_match by default; corroborated when ≥1
//     independent tool agreed (corroborated_by non-empty). "verified" is
//     reserved for an active re-fire confirmation (L2.5) — not set here.
//   - Confidence: a 0–1 scalar = per-tool base reliability bumped by each
//     independent corroborating source.
//
// This gives the security engineer + L2 a single "how much to trust this"
// number, instead of every finding looking equally certain.
type Confidence struct{}

// NewConfidence constructs the hook.
func NewConfidence() *Confidence { return &Confidence{} }

func (*Confidence) Name() string { return "confidence" }

// toolBaseConfidence is the prior trust in a SINGLE hit from each tool,
// before corroboration. Signature/DB tools that emit precise matches rank
// high; broad pattern scanners rank lower (more false positives). Unknown
// tools default to defaultBaseConfidence.
var toolBaseConfidence = map[string]float64{
	"trivy":       0.90, // CVE DB match against a pinned lockfile/image
	"grype":       0.90,
	"osv-scanner": 0.90,
	"sqlmap":      0.85, // confirms injection by differential response
	"nuclei":      0.85, // curated templates, mostly verified matches
	"gitleaks":    0.80, // entropy + rule; some FPs
	"trufflehog":  0.80,
	"cosign":      0.85,
	"dalfox":      0.70, // reflection ≠ always exploitable
	"semgrep":     0.60, // static pattern; needs taint to confirm
	"checkov":     0.65,
	"hadolint":    0.65,
	"dockle":      0.70,
	// A cloud attack path is a deterministic evaluation over COLLECTED inventory — validatePath
	// refuses an edge the graph does not support — so it is precise in the way a DB match is, and
	// belongs above the static pattern scanners. It sits below the tools that observe live behaviour
	// because it still carries the inference the ADR-0024 ladder calls unproven: that the route is
	// USABLE, not merely present.
	//
	// It is listed here because of what taking it out of the "verified" tier would otherwise do. The
	// tier used to be stamped unconditionally, which floored every cloud path at 0.95; making the
	// tier follow the rung (C12) dropped an unchecked path to the 0.50 UNKNOWN-TOOL default, below
	// semgrep — trading an overclaim for an underclaim, on a producer we know a great deal about.
	// With this entry the ladder shows up in confidence too: graph-only 0.75, and the provider-
	// confirmed rung still reaches the 0.95 floor through the verified branch below.
	"cloudagent": 0.75,
}

const defaultBaseConfidence = 0.50

// Finalize stamps verification_status + confidence on every finding.
func (h *Confidence) Finalize(findings []types.Finding) ([]types.Finding, []types.AuditEntry) {
	for i := range findings {
		f := &findings[i]
		if f.VerificationStatus == "" {
			f.VerificationStatus = types.VerificationPatternMatch
		}
		n := len(f.CorroboratedBy) // already deduped by the corroborator hook
		// Cross-tool agreement upgrades pattern_match → corroborated (don't
		// downgrade an already-verified finding).
		if n >= 1 && f.VerificationStatus == types.VerificationPatternMatch {
			f.VerificationStatus = types.VerificationCorroborated
		}
		conf := baseConfidence(f.Tool) + 0.1*float64(n)
		if f.VerificationStatus == types.VerificationVerified {
			conf = math.Max(conf, 0.95) // actively re-fired (L2.5)
		}
		f.Confidence = clampConfidence(conf)
	}
	return findings, nil
}

func baseConfidence(toolName string) float64 {
	if b, ok := toolBaseConfidence[toolName]; ok {
		return b
	}
	return defaultBaseConfidence
}

// clampConfidence bounds to [0, 0.99] and rounds to 2 dp (deterministic for
// reproducibility, §10 — never a raw float that varies in the last digit).
func clampConfidence(c float64) float64 {
	if c > 0.99 {
		c = 0.99
	}
	if c < 0 {
		c = 0
	}
	return math.Round(c*100) / 100
}
