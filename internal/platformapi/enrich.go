package platformapi

import (
	"github.com/ClatTribe/tsengine/internal/l15"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// enrichFindings runs the L1.5 chain (§11) over platform-ingested findings before they are stored.
//
// It now delegates to internal/l15 so the ENGINE scan path can run the identical chain. Its previous
// doc claimed engine-scanned findings "already get this via the sandbox tracer" — they did not; see
// l15.Enrich for what that cost. Kept as a thin wrapper so the ~15 ingest call sites read unchanged.
func enrichFindings(findings []types.Finding) []types.Finding { return l15.Enrich(findings) }
