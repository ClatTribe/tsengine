package rlvr

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A live run recorded through the Recorder must replay byte-identically offline, and grade to the
// SAME verdict — that equivalence is the whole reason the corpus is trustworthy in CI.
func TestRecordReplay_GradesIdentically(t *testing.T) {
	tok := "tsX-canary-abc123"
	url := "http://target/echo?q=" + tok
	live := fakeProber{byURL: map[string]pentest.ProbeResult{
		url: {Status: 200, Body: "reflected: " + tok},
	}}

	// Capture against the "live" target.
	rec := NewRecorder(live)
	ep := Episode{Spec: reflectSpec(url, tok), Truth: TruthVulnerable}
	gLive := Grade(context.Background(), rec, nil, nil, ep)
	if gLive.Verdict != Exploited {
		t.Fatalf("live grade want Exploited, got %s", gLive.Verdict)
	}

	// Serialize the cassette and replay with NO target.
	cas := rec.Cassette()
	blob, _ := json.Marshal(cas)
	var back Cassette
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	rp := NewReplayer(back)
	gReplay := Grade(context.Background(), rp, nil, nil, ep)
	if gReplay.Verdict != gLive.Verdict {
		t.Fatalf("replay verdict %s != live verdict %s", gReplay.Verdict, gLive.Verdict)
	}
}

// A probe absent from the cassette is a corpus GAP → Ungradeable, never a fabricated negative.
func TestReplay_MissingProbeIsUngradeableNotNegative(t *testing.T) {
	tok := "tsX-canary-abc123"
	rp := NewReplayer(Cassette{}) // empty cassette — nothing recorded
	g := Grade(context.Background(), rp, nil, nil, Episode{
		Spec: reflectSpec("http://target/echo?q="+tok, tok), Truth: TruthVulnerable,
	})
	if g.Verdict != Ungradeable {
		t.Fatalf("missing probe must be Ungradeable, got %s", g.Verdict)
	}
}

// A recorded transport error replays as the SAME Ungradeable, so an unreachable target in a
// captured run does not become gradeable on replay.
func TestReplay_RecordedErrorStaysUngradeable(t *testing.T) {
	tok := "tsX-canary-abc123"
	url := "http://down/echo?q=" + tok
	live := fakeProber{fail: map[string]bool{url: true}}
	rec := NewRecorder(live)
	ep := Episode{Spec: reflectSpec(url, tok), Truth: TruthVulnerable}
	_ = Grade(context.Background(), rec, nil, nil, ep) // capture the failure

	rp := NewReplayer(rec.Cassette())
	g := Grade(context.Background(), rp, nil, nil, ep)
	if g.Verdict != Ungradeable {
		t.Fatalf("recorded transport error must replay as Ungradeable, got %s", g.Verdict)
	}
}

// SeedEpisode uses the deterministic substrate proposer; a finding of a class it does not cover
// yields no episode (not an empty guaranteed-negative one).
func TestSeedEpisode_SubstrateArm(t *testing.T) {
	gen := SubstrateSpecGen()

	// An SSTI finding IS covered by HeuristicSpecGen → an episode is seeded.
	ssti := types.Finding{Title: "Server-Side Template Injection", CWE: []string{"CWE-1336"},
		Endpoint: "http://app/render?tpl=x"}
	if _, ok := SeedEpisode("e1", "app", ssti, TruthVulnerable, "c1", gen); !ok {
		t.Fatal("SSTI finding should seed an episode via the substrate proposer")
	}

	// A class the heuristic gen declines yields no episode.
	noise := types.Finding{Title: "informational banner", Endpoint: "http://app/"}
	if _, ok := SeedEpisode("e2", "app", noise, TruthUnknown, "c2", gen); ok {
		t.Fatal("an uncovered class must not seed an episode")
	}
}

// Run grades a batch and returns the matrix in one pass, with ungradeables kept in the slice but
// out of the matrix.
func TestRun_BatchMatrix(t *testing.T) {
	tok := "tok9"
	okURL := "http://t/echo?q=" + tok
	downURL := "http://down/echo?q=" + tok
	pr := fakeProber{
		byURL: map[string]pentest.ProbeResult{okURL: {Status: 200, Body: "x " + tok}},
		fail:  map[string]bool{downURL: true},
	}
	eps := []Episode{
		{ID: "hit", Spec: reflectSpec(okURL, tok), Truth: TruthVulnerable},
		{ID: "down", Spec: reflectSpec(downURL, tok), Truth: TruthVulnerable},
	}
	graded, c := Run(context.Background(), pr, nil, nil, eps)
	if len(graded) != 2 {
		t.Fatalf("want 2 graded episodes, got %d", len(graded))
	}
	if c.TP != 1 || c.Ungradeable != 1 || c.FN != 0 {
		t.Fatalf("matrix wrong: %+v", c)
	}
}
