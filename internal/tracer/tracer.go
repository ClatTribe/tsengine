// Package tracer is the host-side L1.5 enrichment layer. It sits
// between L1 (the orchestrator's raw findings) and the dashboard
// renderer. See CLAUDE.md §11 for the hook chain order and §2.5 for the
// raw-vs-enriched audience split.
//
// The contract:
//
//   - findings_raw      = exactly what L1 emitted, pre-hook. The
//     security-engineer audience reads this.
//   - findings_enriched = post-hook. The compliance audience + L2 read
//     this.
//   - l15_audit_log     = every demotion / dismissal / merge / annotate
//     with a reason, so the security engineer can audit and override.
//
// Ablation: when disabled (TSENGINE_L15_DISABLED=1), enriched == raw and
// no hooks run — this isolates L1's contribution for benchmarking
// (CLAUDE.md §14.1).
package tracer

import "github.com/ClatTribe/tsengine/pkg/types"

// PerFindingHook transforms a single finding as it streams in. Returns
// the (possibly mutated) finding, any audit entries produced, and
// whether to keep the finding (false = drop it).
type PerFindingHook interface {
	Name() string
	Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool)
}

// FinalizeHook runs once over the full enriched set after every finding
// has streamed in. Cross-finding hooks (corroboration, merge) live here
// because they need to see the whole set.
type FinalizeHook interface {
	Name() string
	Finalize(findings []types.Finding) ([]types.Finding, []types.AuditEntry)
}

// Tracer accumulates findings and runs the L1.5 hook chain.
type Tracer struct {
	disabled   bool
	perFinding []PerFindingHook
	finalize   []FinalizeHook

	raw    []types.Finding
	staged []types.Finding
	audit  []types.AuditEntry

	enriched  []types.Finding
	finalized bool
}

// New constructs a Tracer. When disabled is true, the hook lists are
// ignored — Add records the finding into both raw and staged unchanged,
// and Finalize is a no-op, so Enriched() == Raw().
func New(disabled bool, perFinding []PerFindingHook, finalize []FinalizeHook) *Tracer {
	return &Tracer{
		disabled:   disabled,
		perFinding: perFinding,
		finalize:   finalize,
	}
}

// Add records a raw finding and runs the per-finding hook chain.
//
// The raw snapshot is deep-cloned BEFORE any hook runs, so later hook
// mutations (annotations, severity demotes, slice appends) never bleed
// into findings_raw. This is the load-bearing guarantee behind the
// raw-vs-enriched audience split (CLAUDE.md §2.5).
func (t *Tracer) Add(f types.Finding) {
	t.raw = append(t.raw, clone(f))

	if t.disabled {
		t.staged = append(t.staged, f)
		return
	}

	cur := f
	keep := true
	for _, h := range t.perFinding {
		var entries []types.AuditEntry
		cur, entries, keep = h.Apply(cur)
		t.audit = append(t.audit, entries...)
		if !keep {
			break
		}
	}
	if keep {
		t.staged = append(t.staged, cur)
	}
}

// Finalize runs the cross-finding hook chain and freezes the enriched
// set. Idempotent.
func (t *Tracer) Finalize() {
	if t.finalized {
		return
	}
	out := t.staged
	if !t.disabled {
		for _, h := range t.finalize {
			var entries []types.AuditEntry
			out, entries = h.Finalize(out)
			t.audit = append(t.audit, entries...)
		}
	}
	t.enriched = out
	t.finalized = true
}

// Raw returns the pre-L1.5 findings (security-engineer view).
func (t *Tracer) Raw() []types.Finding { return t.raw }

// Enriched returns the post-L1.5 findings (compliance + L2 view).
// Panics if called before Finalize — callers must Finalize first.
func (t *Tracer) Enriched() []types.Finding {
	if !t.finalized {
		t.Finalize()
	}
	return t.enriched
}

// AuditLog returns the L1.5 decision log.
func (t *Tracer) AuditLog() []types.AuditEntry {
	if !t.finalized {
		t.Finalize()
	}
	return t.audit
}

// clone deep-copies the slices + annotation pointers of a Finding so the
// raw snapshot is immune to downstream hook mutation.
func clone(f types.Finding) types.Finding {
	out := f
	out.CWE = cloneStrings(f.CWE)
	out.MITRETechniques = cloneStrings(f.MITRETechniques)
	out.CorroboratedBy = cloneStrings(f.CorroboratedBy)
	if f.ToolArgs != nil {
		m := make(map[string]string, len(f.ToolArgs))
		for k, v := range f.ToolArgs {
			m[k] = v
		}
		out.ToolArgs = m
	}
	// RawOutput is immutable once set by the tool; share the backing.
	// Annotation pointers (ThreatIntel/Compliance/...) are nil pre-hook.
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
