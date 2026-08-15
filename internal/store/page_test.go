package store

import "testing"

// Pagination exists because a workspace that imports its scanner backlog is not small — a measured
// 50,000-finding import serializes to 27MB. These hold the edges, because a paging bug does not look
// like a bug: it looks like findings that quietly do not exist.

func TestPage_ZeroLimitReturnsEverything(t *testing.T) {
	in := []int{1, 2, 3, 4, 5}
	if got := Page(in, FindingFilter{}); len(got) != 5 {
		t.Fatalf("an unpaginated call returned %d of 5 — every existing caller (compliance roll-ups, "+
			"readiness, correlation) needs the whole set and would be silently wrong", len(got))
	}
}

func TestPage_LimitAndOffset(t *testing.T) {
	in := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	got := Page(in, FindingFilter{Limit: 3, Offset: 2})
	if len(got) != 3 || got[0] != 3 || got[2] != 5 {
		t.Errorf("limit=3 offset=2 gave %v, want [3 4 5]", got)
	}
}

// An offset past the end is an EMPTY page, not an error and not a wrapped one. A list UI walking off
// the end must stop, not loop.
func TestPage_OffsetPastEndIsEmpty(t *testing.T) {
	in := []int{1, 2, 3}
	if got := Page(in, FindingFilter{Offset: 99, Limit: 10}); len(got) != 0 {
		t.Errorf("offset past the end returned %v", got)
	}
	if got := Page(in, FindingFilter{Offset: 3}); len(got) != 0 {
		t.Errorf("offset exactly at the end returned %v", got)
	}
}

// A limit larger than the set returns the set, not padding or an error.
func TestPage_LimitLargerThanSet(t *testing.T) {
	in := []int{1, 2}
	if got := Page(in, FindingFilter{Limit: 500}); len(got) != 2 {
		t.Errorf("limit beyond the set returned %d items", len(got))
	}
}

// Empty input is an empty page at any offset — no panic on the slice bounds.
func TestPage_EmptyInput(t *testing.T) {
	if got := Page([]int(nil), FindingFilter{Limit: 10, Offset: 5}); len(got) != 0 {
		t.Errorf("empty input produced %v", got)
	}
}
