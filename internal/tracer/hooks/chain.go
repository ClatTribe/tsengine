package hooks

import "github.com/ClatTribe/tsengine/internal/tracer"

// DefaultPerFinding returns the per-finding hook chain in the canonical
// order from CLAUDE.md §11 (steps 1-7). Steps 8-9 are finalize hooks
// (see DefaultFinalize).
//
//	1+2. fp_filter        (drop + demote)
//	3.   surface_priority (annotate)
//	4.   exploitability   (annotate + may promote)
//	6.   threat_intel     (CVSS/KEV/EPSS)
//	7.   compliance       (control mapping)
//
// (Step 5, corroborator, is a finalize hook — it needs the whole set.)
func DefaultPerFinding() []tracer.PerFindingHook {
	return []tracer.PerFindingHook{
		NewFPFilter(),
		NewSurfacePriority(),
		NewExploitability(),
		NewThreatIntel(),
		NewCompliance(),
	}
}

// DefaultFinalize returns the cross-finding hook chain in canonical
// order:
//
//	5.  corroborator       (cross-tool agreement — runs before merge so
//	    the multi-source signal is captured)
//	8.  post_emit_verifier (wired, inert until L2.5)
//	9.  cross_tool_merge   (collapse exact duplicates)
//	11. confidence         (verification_status + confidence; runs LAST so it
//	    sees the final, merged, corroborated set)
func DefaultFinalize() []tracer.FinalizeHook {
	return []tracer.FinalizeHook{
		NewCorroborator(),
		NewPostEmitVerifier(),
		NewCrossToolMerge(),
		NewConfidence(),
	}
}
