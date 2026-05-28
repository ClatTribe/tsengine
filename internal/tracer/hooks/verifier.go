package hooks

import (
	"os"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// PostEmitVerifier implements hook 8 of CLAUDE.md §11. In its full form
// it re-fires the emitting tool via the tool-replay API with a
// benign-control payload to upgrade a pattern_match finding to verified.
//
// Phase 4 ships it WIRED but inert: re-dispatch needs a sandbox handle
// during enrichment (the tracer runs host-side, after the scan's
// sandbox is torn down), so the real verification loop belongs to a
// dedicated L2.5 pass. The hook is in the chain so the order in §11 is
// honored; it activates only when TSENGINE_L15_POST_EMIT_VERIFY=1, and
// even then is a no-op until the L2.5 re-dispatch lands.
type PostEmitVerifier struct {
	enabled bool
}

// NewPostEmitVerifier reads the opt-in env flag.
func NewPostEmitVerifier() *PostEmitVerifier {
	return &PostEmitVerifier{enabled: os.Getenv("TSENGINE_L15_POST_EMIT_VERIFY") == "1"}
}

func (*PostEmitVerifier) Name() string { return "post_emit_verifier" }

// Finalize is currently a pass-through. When the L2.5 re-dispatch loop
// lands, this will (when enabled) re-fire flagged findings and stamp a
// verified discovery_method.
func (h *PostEmitVerifier) Finalize(findings []types.Finding) ([]types.Finding, []types.AuditEntry) {
	if !h.enabled {
		return findings, nil
	}
	// Re-dispatch loop intentionally deferred — see type doc.
	return findings, nil
}
