package grc

import (
	"reflect"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestComplianceControlsCoversEveryFramework pins the hand-enumerated mirror in complianceControls
// against types.Compliance itself.
//
// The mirror sat at 22 entries while the rest of the product moved to 25, so certin, rbi and sebi
// were silently unmappable in the per-asset compliance view: a tenant who bought this FOR the India
// regulatory frameworks saw them in the compliance report and not per asset — the same finding
// mapped in one place and unmapped in another, with nothing to indicate which was right.
//
// Nothing caught it because the existing frameworks mirror test checks a DIFFERENT function. A
// hand-enumerated list is only as good as whatever stops it drifting, and this one had nothing.
//
// The test drives the REAL function with every field populated, rather than counting `add(` lines:
// a count would pass if someone added a line that mapped the wrong field.
func TestComplianceControlsCoversEveryFramework(t *testing.T) {
	// Populate every []string field on types.Compliance with a marker naming its own field, so a
	// mis-wired mapping (add("rbi", c.SEBI)) shows up as the wrong marker rather than passing.
	c := &types.Compliance{}
	v := reflect.ValueOf(c).Elem()
	rt := v.Type()
	fieldMarker := map[string]string{}
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() != reflect.Slice || v.Field(i).Type().Elem().Kind() != reflect.String {
			continue
		}
		marker := "MARKER-" + rt.Field(i).Name
		v.Field(i).Set(reflect.ValueOf([]string{marker}))
		fieldMarker[rt.Field(i).Name] = marker
	}
	if len(fieldMarker) < 20 {
		t.Fatalf("only found %d framework fields on types.Compliance — this guard has stopped seeing "+
			"its subject and would pass over any drift", len(fieldMarker))
	}

	got := complianceControls(c)

	// Every populated field must surface under some framework key, with ITS OWN marker.
	seen := map[string]bool{}
	for key, vals := range got {
		if len(vals) != 1 {
			t.Errorf("framework %q mapped %d values, want 1", key, len(vals))
			continue
		}
		seen[vals[0]] = true
	}
	var missing []string
	for field, marker := range fieldMarker {
		if !seen[marker] {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		t.Errorf("types.Compliance field(s) never reach the per-asset view: %v\n\n"+
			"Each is a framework a finding can be annotated with and that the per-asset compliance "+
			"page will silently not map — the exact defect that left certin/rbi/sebi invisible while "+
			"the compliance report carried them. Add the missing add(...) line(s) to "+
			"complianceControls.", missing)
	}
	if len(got) != len(fieldMarker) {
		t.Errorf("mirror produced %d framework keys for %d fields", len(got), len(fieldMarker))
	}
}
