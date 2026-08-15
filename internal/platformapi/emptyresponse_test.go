package platformapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func timeoutAfterSeconds(n int) <-chan time.Time {
	return time.After(time.Duration(n) * time.Second)
}

// The empty-workspace contract.
//
// A brand-new workspace has nothing in it, and that is the state every evaluator sees first. Go
// serializes a nil slice as `null`, and a frontend that does .map / .filter / for-of on it throws —
// so "you have no data yet" renders as a broken page rather than an empty one.
//
// This was not hypothetical: /v1/coverage returned {"assets":null,…} and /v1/actions returned
// {"actions":null,…}, and both pages threw on a fresh tenant. The guard existed but only rewrote a
// response that WAS a slice, so it missed every response OBJECT with a nil list field.

// ── THE SHAPE THAT WAS ACTUALLY BROKEN ───────────────────────────────────────────────────────────

type innerRow struct {
	Name  string   `json:"name"`
	Tools []string `json:"tools"` // a per-item list — mapped over exactly like the top-level one
}

type responseObject struct {
	Rows  []innerRow        `json:"rows"`
	Notes map[string]string `json:"notes"`
	Total int               `json:"total"`
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(emptyIfNilSlice(v))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// A response object whose list field is nil must serialize as [] — this is the exact bug.
func TestResponseObject_NilListFieldBecomesEmptyArray(t *testing.T) {
	got := encode(t, responseObject{Total: 0})
	if strings.Contains(got, "null") {
		t.Fatalf("a nil field serialized as null — this is what crashes the page: %s", got)
	}
	if !strings.Contains(got, `"rows":[]`) {
		t.Errorf(`want "rows":[], got %s`, got)
	}
	if !strings.Contains(got, `"notes":{}`) {
		t.Errorf(`want "notes":{}, got %s`, got)
	}
}

// And it must reach INSIDE elements, because a per-row list is mapped over the same way.
func TestNestedElementLists_AreAlsoNormalised(t *testing.T) {
	got := encode(t, responseObject{Rows: []innerRow{{Name: "a"}, {Name: "b", Tools: []string{"nuclei"}}}})
	if strings.Contains(got, "null") {
		t.Fatalf("a nil list inside an element serialized as null: %s", got)
	}
	if !strings.Contains(got, `"tools":[]`) {
		t.Errorf("the empty row's list was not normalised: %s", got)
	}
	if !strings.Contains(got, `"nuclei"`) {
		t.Errorf("normalising destroyed real data: %s", got)
	}
}

// ── THE REAL RESPONSE TYPES, AT THE VALUES A FRESH WORKSPACE PRODUCES ────────────────────────────

// actionsView is what GET /v1/actions returns. On a fresh tenant ListActions yields nil.
func TestActionsView_EmptyTenantHasNoNull(t *testing.T) {
	got := encode(t, actionsView{})
	if strings.Contains(got, "null") {
		t.Fatalf("GET /v1/actions would return null on a new workspace: %s", got)
	}
	if !strings.Contains(got, `"actions":[]`) {
		t.Errorf(`want "actions":[], got %s`, got)
	}
}

// ── THE PROPERTIES THAT MUST SURVIVE ─────────────────────────────────────────────────────────────

// Normalising must not alter real data — only absence.
func TestPopulatedResponse_IsUnchanged(t *testing.T) {
	in := responseObject{
		Rows:  []innerRow{{Name: "web", Tools: []string{"nuclei", "katana"}}},
		Notes: map[string]string{"k": "v"},
		Total: 1,
	}
	before, _ := json.Marshal(in)
	after := encode(t, in)
	if string(before) != after {
		t.Errorf("a populated response was modified:\n before %s\n after  %s", before, after)
	}
}

// The caller's own value must not be mutated — we copy before filling.
func TestCallerValueIsNotMutated(t *testing.T) {
	in := responseObject{}
	_ = encode(t, in)
	if in.Rows != nil {
		t.Error("emptyIfNilSlice mutated the caller's struct instead of a copy")
	}
}

// The original top-level-slice behaviour must still hold.
func TestTopLevelNilSlice_StillBecomesEmptyArray(t *testing.T) {
	var rows []innerRow
	if got := encode(t, rows); got != "[]" {
		t.Errorf("top-level nil slice = %s, want []", got)
	}
}

// A nil interface must stay nil — respond(w, nil, err) relies on it, and inventing {} there would
// turn an error path into a fake empty success.
func TestNilInput_StaysNil(t *testing.T) {
	if emptyIfNilSlice(nil) != nil {
		t.Error("nil was replaced with a value")
	}
}

// Pointers are followed, but a nil pointer must stay null — absent OBJECT and empty LIST are
// different facts, and only the second one is safe to invent.
func TestNilPointer_IsNotInvented(t *testing.T) {
	type withPtr struct {
		Detail *innerRow `json:"detail"`
	}
	got := encode(t, withPtr{})
	if !strings.Contains(got, `"detail":null`) {
		t.Errorf("a nil pointer was replaced with an object — that invents data: %s", got)
	}

	// A non-nil pointer's own nil lists, however, must be reached.
	got = encode(t, withPtr{Detail: &innerRow{Name: "x"}})
	if !strings.Contains(got, `"tools":[]`) {
		t.Errorf("the walk did not follow a live pointer: %s", got)
	}
}

// A self-referential type must terminate rather than hang. The depth cap is the only thing standing
// between a recursive response shape and a wedged request.
func TestRecursiveType_Terminates(t *testing.T) {
	type node struct {
		Kids []*node  `json:"kids"`
		Tags []string `json:"tags"`
	}
	deep := &node{}
	cur := deep
	for i := 0; i < 40; i++ {
		next := &node{}
		cur.Kids = []*node{next}
		cur = next
	}
	done := make(chan string, 1)
	go func() { done <- encode(t, deep) }()
	select {
	case <-done:
	case <-timeoutAfterSeconds(5):
		t.Fatal("emptyIfNilSlice did not terminate on a deeply nested value")
	}
}

// ── THE SHAPE THE CODEBASE ACTUALLY USES ─────────────────────────────────────────────────────────

// #1129 normalised struct fields and slice elements, and skipped map VALUES because they are not
// addressable. But map[string]any is the most common response shape here — 71 handlers emit one — so
// `writeJSON(w, 200, map[string]any{"threats": threats})` with a nil slice was still sending
// `"threats": null` to a frontend that maps over it. A fix covering one of two exits is not a fix.
func TestNilSliceInsideAMap_IsNormalised(t *testing.T) {
	var threats []innerRow
	got := encode(t, map[string]any{"events_ingested": 1, "threats": threats})
	if strings.Contains(got, "null") {
		t.Fatalf("a nil slice inside map[string]any serialized as null: %s", got)
	}
	if !strings.Contains(got, `"threats":[]`) {
		t.Errorf(`want "threats":[], got %s`, got)
	}
}

// The value inside a map[string]any is an interface; without unwrapping it, every entry looks opaque
// and nothing is normalised.
func TestNilSliceInsideAMap_UnwrapsTheInterface(t *testing.T) {
	var rows []innerRow
	var m map[string]string
	got := encode(t, map[string]any{"rows": rows, "meta": m, "n": 3})
	for _, want := range []string{`"rows":[]`, `"meta":{}`, `"n":3`} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in %s", want, got)
		}
	}
}

// Nested one level deeper — a map holding a struct whose field is nil.
func TestNilSliceInAStructInsideAMap(t *testing.T) {
	got := encode(t, map[string]any{"result": responseObject{Total: 1}})
	if strings.Contains(got, "null") {
		t.Errorf("a nil field on a struct inside a map serialized as null: %s", got)
	}
}

// Real data inside a map must survive untouched.
func TestPopulatedMap_IsUnchanged(t *testing.T) {
	in := map[string]any{"rows": []innerRow{{Name: "a", Tools: []string{"nuclei"}}}, "n": 1}
	before, _ := json.Marshal(in)
	if after := encode(t, in); string(before) != after {
		t.Errorf("a populated map was modified:\n before %s\n after  %s", before, after)
	}
}
