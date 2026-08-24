package platformapi

import "reflect"

// countJSONFields counts a struct's exported fields — used by mirror guards to notice a field added
// on one side of a conversion and not the other.
func countJSONFields(v any) int {
	t := reflect.TypeOf(v)
	n := 0
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).IsExported() {
			n++
		}
	}
	return n
}
