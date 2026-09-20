package backport

import (
	"strings"
	"testing"
)

// THE PROPERTY THAT MATTERS: a hunk derived from before→after, relocated onto that same `before` and
// applied, must reproduce `after` exactly. If this does not hold, every backport plan is built on a
// hunk that does not describe the fix it came from.
func TestHunkBetween_RoundTripsThroughLocateAndApply(t *testing.T) {
	before := lines(`
package main

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT * FROM users WHERE id = " + q)
	render(w, row)
}`)
	after := lines(`
package main

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT * FROM users WHERE id = ?", q)
	render(w, row)
}`)

	h, ok := HunkBetween("handler.go", before, after)
	if !ok {
		t.Fatal("a real change must yield a hunk")
	}
	if len(h.Removed) != 1 || !strings.Contains(h.Removed[0], `" + q`) {
		t.Errorf("Removed should be the vulnerable line, got %q", h.Removed)
	}
	if len(h.Added) != 1 || !strings.Contains(h.Added[0], `?", q`) {
		t.Errorf("Added should be the parameterised line, got %q", h.Added)
	}
	if len(h.Before) == 0 || len(h.After) == 0 {
		t.Error("the hunk carries no context, so Locate cannot disambiguate candidate sites")
	}

	r := Locate(before, h)
	if r.Verdict != VerdictClean {
		t.Fatalf("a hunk derived from this exact file must locate cleanly in it, got %s (%s)", r.Verdict, r.Reason)
	}
	got, applied := Apply(before, h, r)
	if !applied {
		t.Fatal("Apply refused a hunk derived from the very file it was derived from")
	}
	if strings.Join(got, "\n") != strings.Join(after, "\n") {
		t.Errorf("round trip did not reproduce `after`:\n got: %q\nwant: %q", got, after)
	}
}

// An identical pair is NOT a hunk. Returning an empty one would make Locate report "hunk has no
// changes" → every branch not_applicable, which reads exactly like "no branch is affected" — a
// false all-clear manufactured from a no-op (§10).
func TestHunkBetween_IdenticalVersionsYieldNoHunk(t *testing.T) {
	same := lines("\na\nb\nc")
	if _, ok := HunkBetween("f.go", same, same); ok {
		t.Error("identical versions must not produce a hunk")
	}
}

// A pure insertion (nothing removed) is anchored on its preceding context — Locate has a dedicated
// branch for it, and it only works when Before is populated.
func TestHunkBetween_PureInsertionCarriesAnchoringContext(t *testing.T) {
	before := lines("\nsetup()\nserve()\ndone()")
	after := lines("\nsetup()\nauthCheck()\nserve()\ndone()")

	h, ok := HunkBetween("m.go", before, after)
	if !ok {
		t.Fatal("an insertion is a change")
	}
	if len(h.Removed) != 0 {
		t.Errorf("a pure insertion removes nothing, got %q", h.Removed)
	}
	if len(h.Before) == 0 {
		t.Fatal("an insertion with no preceding context cannot be anchored — Locate would refuse it")
	}
	r := Locate(before, h)
	if r.Verdict != VerdictClean && r.Verdict != VerdictOffset {
		t.Fatalf("insertion should locate, got %s (%s)", r.Verdict, r.Reason)
	}
	got, applied := Apply(before, h, r)
	if !applied || strings.Join(got, "\n") != strings.Join(after, "\n") {
		t.Errorf("insertion round trip failed: %q", got)
	}
}

// The derived hunk relocates onto a DRIFTED branch — the whole point of backporting. The branch has
// the same vulnerable line further down, surrounded by the same context.
func TestHunkBetween_RelocatesOntoADriftedBranch(t *testing.T) {
	before := lines(`
func handler() {
	q := get("id")
	row := db.Query("SELECT * FROM users WHERE id = " + q)
	render(row)
}`)
	after := lines(`
func handler() {
	q := get("id")
	row := db.Query("SELECT * FROM users WHERE id = ?", q)
	render(row)
}`)
	// The release branch: same function, preceded by extra code (so line numbers differ).
	branch := lines(`
// legacy header
import "db"

func handler() {
	q := get("id")
	row := db.Query("SELECT * FROM users WHERE id = " + q)
	render(row)
}`)

	h, _ := HunkBetween("h.go", before, after)
	r := Locate(branch, h)
	if r.Verdict != VerdictOffset && r.Verdict != VerdictClean {
		t.Fatalf("the fix should relocate onto the drifted branch, got %s (%s)", r.Verdict, r.Reason)
	}
	got, ok := Apply(branch, h, r)
	if !ok {
		t.Fatal("Apply refused a located hunk on the drifted branch")
	}
	if !strings.Contains(strings.Join(got, "\n"), `?", q`) {
		t.Error("the branch was not actually patched")
	}
	if strings.Contains(strings.Join(got, "\n"), `" + q`) {
		t.Error("the vulnerable line survived the backport")
	}
}

// A branch that ALREADY has the fix must be recognised — re-applying a security patch is a real
// damaging failure mode, and PlanBackports emits no action for it.
func TestHunkBetween_AlreadyFixedBranchIsDetected(t *testing.T) {
	before := lines("\na\nvuln(x)\nb")
	after := lines("\na\nsafe(x)\nb")
	h, _ := HunkBetween("f.go", before, after)

	if r := Locate(after, h); r.Verdict != VerdictAlreadyApplied {
		t.Errorf("a branch already carrying the fix must read already_applied, got %s (%s)", r.Verdict, r.Reason)
	}
}
