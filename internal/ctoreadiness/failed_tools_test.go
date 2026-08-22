package ctoreadiness

import (
	"strings"
	"testing"
)

// observedItem finds a real observed row that names tools, so the test exercises the shipped
// checklist rather than a fixture invented to pass.
func observedItem(t *testing.T) Item {
	t.Helper()
	for _, it := range Items() {
		if it.Evidence == EvidenceObserved && len(it.Tools) > 0 && len(it.Needs) > 0 {
			return it
		}
	}
	t.Fatal("no observed item with named tools — if the checklist changed shape, update this test " +
		"rather than leaving it asserting nothing")
	return Item{}
}

// The row's whole value is that it NAMES what established the tick. A tick resting on a tool that
// produced nothing is worth less than no tick at all.
//
// Scanned answers "did the engine run against this asset type", which is one level too coarse: an
// engagement completes and marks the type scanned even when the tool answering this row never ran —
// a per-tool timeout, a crash, or a binary missing from the sandbox image. The row then read
// "Checked by <tools> — nothing open" while naming a tool that produced nothing.
func TestObservedRow_DoesNotCiteAToolThatDidNotRun(t *testing.T) {
	it := observedItem(t)
	in := Input{
		Stage:        TierSeriesC,
		AssetTypes:   map[string]bool{},
		ConnKinds:    map[string]bool{},
		Scanned:      map[string]bool{},
		FindingTools: map[string]int{},
		FindingRules: map[string]int{},
		Capabilities: map[string]bool{},
		FailedTools:  map[string]bool{it.Tools[0]: true},
	}
	for _, n := range it.Needs {
		in.AssetTypes[n], in.ConnKinds[n], in.Scanned[n] = true, true, true
	}

	r := rowFor(t, it.ID, in)
	if r.Status == StatusPass {
		t.Fatalf("row %q reported PASS citing %q, which was dispatched and produced nothing: %q",
			it.ID, it.Tools[0], r.Detail)
	}
	if !strings.Contains(r.Detail, it.Tools[0]) || !strings.Contains(r.Detail, "did not run") {
		t.Errorf("the detail must NAME the tool that did not run so it is actionable, got %q", r.Detail)
	}
}

// The control: with the same tools running fine, the row still passes. This must not become a way to
// make the whole checklist read not-checked.
func TestObservedRow_StillPassesWhenItsToolsRan(t *testing.T) {
	it := observedItem(t)
	in := Input{
		Stage:        TierSeriesC,
		AssetTypes:   map[string]bool{},
		ConnKinds:    map[string]bool{},
		Scanned:      map[string]bool{},
		FindingTools: map[string]int{},
		FindingRules: map[string]int{},
		Capabilities: map[string]bool{},
		FailedTools:  map[string]bool{"some-unrelated-tool": true},
	}
	for _, n := range it.Needs {
		in.AssetTypes[n], in.ConnKinds[n], in.Scanned[n] = true, true, true
	}
	if r := rowFor(t, it.ID, in); r.Status != StatusPass {
		t.Errorf("this row's own tools all ran — an unrelated tool failing elsewhere must not void it: "+
			"status=%s detail=%q", r.Status, r.Detail)
	}
}

func rowFor(t *testing.T, id string, in Input) Result {
	t.Helper()
	for _, r := range Assess(in) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("row %q not produced", id)
	return Result{}
}
