package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestWithoutOwnProbes(t *testing.T) {
	own := map[string]bool{"mycanary": true}
	events := []platform.RuntimeEvent{
		{ID: "a", Endpoint: "https://app/x", Marker: "mycanary"},     // ours — drop
		{ID: "b", Endpoint: "https://app/x", Marker: ""},             // real attack, no marker — keep
		{ID: "c", Endpoint: "https://app/x", Marker: "attackerJunk"}, // not our canary — keep
	}
	got := WithoutOwnProbes(events, own)
	if len(got) != 2 {
		t.Fatalf("want 2 kept, got %d", len(got))
	}
	for _, e := range got {
		if e.ID == "a" {
			t.Fatal("our own probe (marker=mycanary) must be dropped")
		}
	}
	// Empty marker set is a no-op (keeps everything).
	if len(WithoutOwnProbes(events, nil)) != 3 {
		t.Fatal("nil marker set must keep all events")
	}
}

// The bug this closes: our own validation probe, reflected in a WAF log, must not flag an issue as
// "under active attack in production".
func TestOwnProbeDoesNotFlagAttacked(t *testing.T) {
	issues := []Issue{{Endpoint: "https://app.acme.com/search"}}
	ownProbe := []platform.RuntimeEvent{{Endpoint: "https://app.acme.com/search", Marker: "ourcanary"}}

	// Unfiltered: it would (wrongly) flag attacked.
	if n := AnnotateRuntime(issues, ownProbe); n != 1 {
		t.Fatalf("precondition: unfiltered own-probe flags attacked, got %d", n)
	}
	// Filtered: our own probe is excluded, so nothing is flagged.
	issues2 := []Issue{{Endpoint: "https://app.acme.com/search"}}
	filtered := WithoutOwnProbes(ownProbe, map[string]bool{"ourcanary": true})
	if n := AnnotateRuntime(issues2, filtered); n != 0 {
		t.Fatalf("our own probe must not flag attacked after filtering, got %d", n)
	}
	if issues2[0].Attacked {
		t.Fatal("issue must not be marked Attacked by our own probe")
	}
}
