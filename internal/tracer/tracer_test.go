package tracer

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- test hooks --------------------------------------------------

// demoteHook lowers every finding to info and logs it.
type demoteHook struct{}

func (demoteHook) Name() string { return "test-demote" }
func (demoteHook) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	from := f.Severity
	f.Severity = types.SeverityInfo
	return f, []types.AuditEntry{{
		FindingID: f.ID, Action: "demote", FromSeverity: from, ToSeverity: types.SeverityInfo, Rule: "test",
	}}, true
}

// dropHook drops findings whose RuleID == "drop-me".
type dropHook struct{}

func (dropHook) Name() string { return "test-drop" }
func (dropHook) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	if f.RuleID == "drop-me" {
		return f, []types.AuditEntry{{FindingID: f.ID, Action: "dismiss", Rule: "test"}}, false
	}
	return f, nil, true
}

// annotateFinalize sets CorroboratedBy on every finding.
type annotateFinalize struct{}

func (annotateFinalize) Name() string { return "test-finalize" }
func (annotateFinalize) Finalize(in []types.Finding) ([]types.Finding, []types.AuditEntry) {
	for i := range in {
		in[i].CorroboratedBy = []string{"x"}
	}
	return in, []types.AuditEntry{{Action: "annotate", Rule: "test"}}
}

func f(id, rule string, sev types.Severity) types.Finding {
	return types.Finding{ID: id, RuleID: rule, Tool: "t", Severity: sev, Title: id, DiscoveredAt: time.Now()}
}

// --- tests -------------------------------------------------------

func TestTracer_Disabled_EnrichedEqualsRaw(t *testing.T) {
	tr := New(true, []PerFindingHook{demoteHook{}}, []FinalizeHook{annotateFinalize{}})
	tr.Add(f("f-1", "r1", types.SeverityHigh))
	tr.Finalize()

	if len(tr.Raw()) != 1 || len(tr.Enriched()) != 1 {
		t.Fatalf("raw=%d enriched=%d", len(tr.Raw()), len(tr.Enriched()))
	}
	// Disabled: no demotion, no annotation, no audit.
	if tr.Enriched()[0].Severity != types.SeverityHigh {
		t.Errorf("disabled tracer should not demote; got %q", tr.Enriched()[0].Severity)
	}
	if tr.Enriched()[0].CorroboratedBy != nil {
		t.Errorf("disabled tracer should not annotate")
	}
	if len(tr.AuditLog()) != 0 {
		t.Errorf("disabled tracer should log nothing; got %d", len(tr.AuditLog()))
	}
}

func TestTracer_PerFindingHooksRunInOrder(t *testing.T) {
	tr := New(false, []PerFindingHook{demoteHook{}}, nil)
	tr.Add(f("f-1", "r1", types.SeverityCritical))
	tr.Finalize()

	if tr.Enriched()[0].Severity != types.SeverityInfo {
		t.Errorf("demote hook didn't run; got %q", tr.Enriched()[0].Severity)
	}
	// Raw must be untouched.
	if tr.Raw()[0].Severity != types.SeverityCritical {
		t.Errorf("raw was mutated by hook: got %q, want critical", tr.Raw()[0].Severity)
	}
	if len(tr.AuditLog()) != 1 || tr.AuditLog()[0].Action != "demote" {
		t.Errorf("audit log: %+v", tr.AuditLog())
	}
}

func TestTracer_DropHookRemovesFromEnrichedNotRaw(t *testing.T) {
	tr := New(false, []PerFindingHook{dropHook{}}, nil)
	tr.Add(f("f-1", "keep", types.SeverityHigh))
	tr.Add(f("f-2", "drop-me", types.SeverityHigh))
	tr.Finalize()

	if len(tr.Raw()) != 2 {
		t.Errorf("raw should keep all findings; got %d", len(tr.Raw()))
	}
	if len(tr.Enriched()) != 1 || tr.Enriched()[0].ID != "f-1" {
		t.Errorf("enriched should drop f-2; got %+v", tr.Enriched())
	}
	if len(tr.AuditLog()) != 1 || tr.AuditLog()[0].Action != "dismiss" {
		t.Errorf("dismiss not logged: %+v", tr.AuditLog())
	}
}

func TestTracer_FinalizeHookRuns(t *testing.T) {
	tr := New(false, nil, []FinalizeHook{annotateFinalize{}})
	tr.Add(f("f-1", "r1", types.SeverityHigh))
	tr.Finalize()

	if tr.Enriched()[0].CorroboratedBy == nil {
		t.Error("finalize hook didn't annotate")
	}
	// Raw untouched.
	if tr.Raw()[0].CorroboratedBy != nil {
		t.Error("raw was mutated by finalize hook")
	}
}

func TestTracer_RawDeepClone_SliceIsolation(t *testing.T) {
	// A hook that appends to CWE must not affect the raw snapshot.
	appendCWE := perFindingFunc(func(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
		f.CWE = append(f.CWE, "CWE-999")
		return f, nil, true
	})
	tr := New(false, []PerFindingHook{appendCWE}, nil)
	in := f("f-1", "r1", types.SeverityHigh)
	in.CWE = []string{"CWE-79"}
	tr.Add(in)
	tr.Finalize()

	if len(tr.Raw()[0].CWE) != 1 {
		t.Errorf("raw CWE mutated: %v", tr.Raw()[0].CWE)
	}
	if len(tr.Enriched()[0].CWE) != 2 {
		t.Errorf("enriched CWE should have appended entry: %v", tr.Enriched()[0].CWE)
	}
}

func TestTracer_FinalizeIdempotent(t *testing.T) {
	tr := New(false, nil, []FinalizeHook{annotateFinalize{}})
	tr.Add(f("f-1", "r1", types.SeverityHigh))
	tr.Finalize()
	n := len(tr.AuditLog())
	tr.Finalize() // second call must not re-run hooks
	if len(tr.AuditLog()) != n {
		t.Errorf("Finalize not idempotent: audit grew from %d to %d", n, len(tr.AuditLog()))
	}
}

// perFindingFunc adapts a func to the PerFindingHook interface for tests.
type perFindingFunc func(types.Finding) (types.Finding, []types.AuditEntry, bool)

func (perFindingFunc) Name() string { return "test-func" }
func (fn perFindingFunc) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	return fn(f)
}
