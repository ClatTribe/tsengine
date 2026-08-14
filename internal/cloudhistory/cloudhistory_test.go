package cloudhistory

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func at(min int) time.Time { return time.Date(2026, 1, 1, 0, min, 0, 0, time.UTC) }

func digest(tenant string, min int, res map[string]ResourceState) Digest {
	return Digest{TenantID: tenant, CapturedAt: at(min), Resources: res}
}

// THE QUESTION THIS EXISTS TO ANSWER: when did this bucket become public?
func TestWhenChanged_AnswersWhenABucketBecamePublic(t *testing.T) {
	timeline := []Digest{
		digest("t1", 0, map[string]ResourceState{"bucket-a": {Type: "s3", Sensitive: "high"}}),
		digest("t1", 10, map[string]ResourceState{"bucket-a": {Type: "s3", Sensitive: "high"}}),
		digest("t1", 20, map[string]ResourceState{"bucket-a": {Type: "s3", Sensitive: "high", Public: true}}),
	}
	got := WhenChanged(timeline, "bucket-a")
	if len(got) != 1 {
		t.Fatalf("want exactly one transition, got %d: %+v", len(got), got)
	}
	if !got[0].At.Equal(at(20)) {
		t.Errorf("transition dated %v, want the capture where it flipped (%v)", got[0].At, at(20))
	}
	if !strings.Contains(got[0].What, "internet-facing") {
		t.Errorf("the change does not say what happened in a reader's terms: %q", got[0].What)
	}
}

// An identity gaining a path to admin is the other question asked in every incident.
func TestDiff_PrivilegeGainIsRecorded(t *testing.T) {
	prev := digest("t1", 0, map[string]ResourceState{"role-x": {Type: "iam_role"}})
	cur := digest("t1", 10, map[string]ResourceState{"role-x": {Type: "iam_role", Privileged: true}})
	got := Diff(prev, cur)
	if len(got) != 1 || !strings.Contains(got[0].What, "gained privilege") {
		t.Errorf("privilege gain not recorded as such: %+v", got)
	}
}

// AN UNCHANGED ESTATE MUST RECORD NOTHING. Without this the timeline becomes one row per scan, and
// "when did this change" degenerates into "here is every time we looked".
func TestAppend_UnchangedEstateRecordsNothing(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	d := digest("t1", 0, map[string]ResourceState{"a": {Public: true}})

	if rec, _ := st.Append(ctx, d); !rec {
		t.Fatal("the first capture must be recorded")
	}
	same := digest("t1", 99, map[string]ResourceState{"a": {Public: true}}) // later time, same state
	if rec, _ := st.Append(ctx, same); rec {
		t.Error("an unchanged estate was recorded — the timeline is a record of CHANGE, not of scans")
	}
	tl, _ := st.Timeline(ctx, "t1")
	if len(tl) != 1 {
		t.Errorf("timeline has %d captures, want 1", len(tl))
	}
}

// A resource that vanishes while public must be recorded — it is either genuinely gone or the collector
// lost visibility, and the second must never read as "fixed".
func TestDiff_DisappearanceIsNotSilentlyGood(t *testing.T) {
	prev := digest("t1", 0, map[string]ResourceState{"gone": {Public: true, Type: "s3"}})
	cur := digest("t1", 10, map[string]ResourceState{})
	got := Diff(prev, cur)
	if len(got) != 1 {
		t.Fatalf("a public resource disappearing produced no change: %+v", got)
	}
	if !strings.Contains(got[0].What, "no longer visible") {
		t.Errorf("disappearance does not warn that it may be lost visibility rather than a fix: %q", got[0].What)
	}
}

// A new resource that arrives BENIGN must not spam the timeline; one that arrives exposed must.
func TestDiff_NewResourcesOnlyMatterWhenExposed(t *testing.T) {
	prev := digest("t1", 0, map[string]ResourceState{})
	cur := digest("t1", 10, map[string]ResourceState{
		"quiet": {Type: "s3"},
		"loud":  {Type: "s3", Public: true},
	})
	got := Diff(prev, cur)
	if len(got) != 1 || got[0].ResourceID != "loud" {
		t.Errorf("want only the exposed arrival reported, got %+v", got)
	}
}

// Retention must bound growth, and must keep the NEWEST (the drift baseline lives there).
func TestAppend_RetentionKeepsTheNewest(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	st.Retain = 3
	for i := 0; i < 10; i++ {
		// each capture differs, so each is recorded
		_, _ = st.Append(ctx, digest("t1", i, map[string]ResourceState{"a": {Type: "s3", Sensitive: string(rune('a' + i))}}))
	}
	tl, _ := st.Timeline(ctx, "t1")
	if len(tl) != 3 {
		t.Fatalf("retention not applied: %d captures", len(tl))
	}
	if !tl[len(tl)-1].CapturedAt.Equal(at(9)) {
		t.Errorf("newest capture was dropped (%v) — the drift baseline must survive trimming", tl[len(tl)-1].CapturedAt)
	}
}

// Tenant isolation (§18.2 inv. 2).
func TestTimeline_IsTenantScoped(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_, _ = st.Append(ctx, digest("t1", 0, map[string]ResourceState{"mine": {Public: true}}))
	_, _ = st.Append(ctx, digest("other", 0, map[string]ResourceState{"theirs": {Public: true}}))
	tl, _ := st.Timeline(ctx, "t1")
	for _, d := range tl {
		if _, leaked := d.Resources["theirs"]; leaked {
			t.Error("ISOLATION: another tenant's resource appeared in this timeline")
		}
	}
}

// A resource that never changed returns nothing — a real answer, not a failure.
func TestWhenChanged_NeverChangedIsEmpty(t *testing.T) {
	timeline := []Digest{
		digest("t1", 0, map[string]ResourceState{"steady": {Type: "s3"}}),
		digest("t1", 10, map[string]ResourceState{"steady": {Type: "s3"}}),
	}
	if got := WhenChanged(timeline, "steady"); len(got) != 0 {
		t.Errorf("invented a transition for an unchanged resource: %+v", got)
	}
}

// DigestOf must reduce a real graph, and a nil snapshot must not panic.
func TestDigestOf_ReducesAGraph(t *testing.T) {
	inv := cloudgraph.Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []cloudgraph.InvResource{
			{ID: "b", Kind: cloudgraph.KindData, Type: "s3", Public: true, Sensitive: cloudgraph.SensHigh},
		},
	}
	d := DigestOf(cloudgraph.Ingest(inv), "t1", "aws", "1", at(0))
	rs, ok := d.Resources["b"]
	if !ok {
		t.Fatal("resource missing from the digest")
	}
	if !rs.Public || rs.Sensitive != "high" {
		t.Errorf("security attributes lost in reduction: %+v", rs)
	}
	if got := DigestOf(nil, "t1", "aws", "1", at(0)); len(got.Resources) != 0 {
		t.Error("a nil snapshot should digest to an empty state, not panic or invent")
	}
}
