package training

import "reflect"

// hasField reports whether Summary carries a field whose name contains sub. Used by the
// no-combined-rate test: the refusal is structural, so the check has to look at the struct rather
// than at one rendered string.
func hasField(s Summary, sub string) bool {
	t := reflect.TypeOf(s)
	for i := 0; i < t.NumField(); i++ {
		if containsFold(t.Field(i).Name, sub) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	ls, lsub := lower(s), lower(sub)
	return len(lsub) > 0 && len(ls) >= len(lsub) && indexOf(ls, lsub) >= 0
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
