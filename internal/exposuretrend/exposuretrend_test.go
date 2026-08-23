package exposuretrend_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/exposuretrend"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func ep(day string, scope string, opened, closed, persisted int) platform.EpisodeRecord {
	t, _ := time.Parse(time.DateOnly, day)
	e := platform.EpisodeRecord{TenantID: "t1", Scope: scope, RanAt: t}
	d := &ledger.SecurityStateDelta{Persisted: persisted}
	for i := 0; i < opened; i++ {
		d.Opened = append(d.Opened, "o")
	}
	for i := 0; i < closed; i++ {
		d.Closed = append(d.Closed, "c")
	}
	e.Delta = d
	return e
}

func unscored(day, scope, why string) platform.EpisodeRecord {
	t, _ := time.Parse(time.DateOnly, day)
	return platform.EpisodeRecord{TenantID: "t1", Scope: scope, RanAt: t, Unscored: why}
}

// THE point of a series: direction. A lifetime total cannot say whether this week is better.
func TestCompute_SeriesShowsDirectionByDay(t *testing.T) {
	tr := exposuretrend.Compute([]platform.EpisodeRecord{
		ep("2026-08-20", "cloud:t1", 5, 1, 10),
		ep("2026-08-22", "cloud:t1", 1, 6, 4),
	}, nil, "")
	if len(tr.Points) != 2 {
		t.Fatalf("want two days, got %+v", tr.Points)
	}
	if tr.Points[0].Day != "2026-08-20" || tr.Points[1].Day != "2026-08-22" {
		t.Fatalf("points must be ordered by day, got %+v", tr.Points)
	}
	if tr.Points[0].Net() != -4 {
		t.Errorf("day one grew exposure: want net -4, got %d", tr.Points[0].Net())
	}
	if tr.Points[1].Net() != 5 {
		t.Errorf("day two reduced it: want net 5, got %d", tr.Points[1].Net())
	}
}

// THE honesty rule. Closed counts issues that STOPPED APPEARING — a descoped asset and a degraded
// scan produce it too. The strong signal sits beside it and is never folded in.
func TestCompute_ConfirmedFixedIsSeparateFromClosed(t *testing.T) {
	acts := []platform.Action{
		{Verification: &platform.FixVerification{Status: platform.FixStatusFixed}},
		{Verification: &platform.FixVerification{Status: "closed_with_proof"}},
		{Verification: &platform.FixVerification{Status: platform.FixStatusStillPresent}},
		{Verification: &platform.FixVerification{Status: platform.FixStatusRescanUnconfirmed}},
		{}, // never verified
	}
	tr := exposuretrend.Compute([]platform.EpisodeRecord{ep("2026-08-20", "s", 0, 9, 0)}, acts, "")
	if tr.ConfirmedFixed != 2 {
		t.Fatalf("only re-test-proven closures count as fixed, got %d", tr.ConfirmedFixed)
	}
	if tr.Points[0].Closed != 9 {
		t.Errorf("closed must stay its own number, got %d", tr.Points[0].Closed)
	}
	if !strings.Contains(tr.Caveat, "STOPPED APPEARING") {
		t.Errorf("the caveat must say what closed actually means, got: %s", tr.Caveat)
	}
	// A withheld confirmation (ADR 0025 F1) is not a fix here either.
	if tr.ConfirmedFixed > 2 {
		t.Error("an unconfirmed rescan must not be counted as a confirmed fix")
	}
}

// An unmeasured run is not a quiet one. Counted as zero it reads as "nothing changed", which is the
// opposite fact.
func TestCompute_UnscoredRunsAreCountedNotSilent(t *testing.T) {
	tr := exposuretrend.Compute([]platform.EpisodeRecord{
		ep("2026-08-20", "s", 3, 0, 0),
		unscored("2026-08-20", "s", "posture could not be censused on both sides"),
	}, nil, "")
	if tr.Unscored != 1 || tr.Points[0].Unscored != 1 {
		t.Fatalf("the unmeasured run must be counted, got trend=%d point=%d", tr.Unscored, tr.Points[0].Unscored)
	}
	if tr.Points[0].Episodes != 2 {
		t.Errorf("both runs happened: want 2 episodes, got %d", tr.Points[0].Episodes)
	}
	if tr.Points[0].Opened != 3 {
		t.Errorf("an unscored run must contribute no movement, got opened=%d", tr.Points[0].Opened)
	}
}

// Episodes from different scopes census different things and are not comparable. Mixing them
// silently would average incomparable runs into one confident line.
func TestCompute_MixedScopesAreDeclaredAndFilterable(t *testing.T) {
	eps := []platform.EpisodeRecord{
		ep("2026-08-20", "cloud:t1", 4, 0, 0),
		ep("2026-08-20", "code:t1", 0, 4, 0),
	}
	all := exposuretrend.Compute(eps, nil, "")
	if !all.Mixed || len(all.ScopesIncluded) != 2 {
		t.Fatalf("a mixed series must say so, got mixed=%v scopes=%v", all.Mixed, all.ScopesIncluded)
	}
	one := exposuretrend.Compute(eps, nil, "cloud:t1")
	if one.Mixed || len(one.ScopesIncluded) != 1 {
		t.Errorf("a filtered series must not be mixed, got %+v", one.ScopesIncluded)
	}
	if one.Points[0].Opened != 4 || one.Points[0].Closed != 0 {
		t.Errorf("the filter must exclude the other scope, got %+v", one.Points[0])
	}
}

// Nothing to report reports nothing — not a flat, reassuring line at zero.
func TestCompute_EmptyCorpusIsEmpty(t *testing.T) {
	tr := exposuretrend.Compute(nil, nil, "")
	if len(tr.Points) != 0 || tr.ConfirmedFixed != 0 {
		t.Fatalf("an empty corpus must produce an empty series, got %+v", tr)
	}
	if tr.Caveat == "" {
		t.Error("the caveat must ride even on an empty trend")
	}
}

// Net() computed direction and nothing called it — a method with a carefully argued name and no
// caller. It is now serialised, so the reader sees direction without doing arithmetic across a
// week of rows.
func TestCompute_NetChangeIsSerialised(t *testing.T) {
	tr := exposuretrend.Compute([]platform.EpisodeRecord{
		ep("2026-08-20", "s", 5, 1, 0), // exposure grew
		ep("2026-08-22", "s", 1, 6, 0), // exposure shrank
	}, nil, "")
	if tr.Points[0].NetChange != -4 {
		t.Errorf("day one grew: want -4, got %d", tr.Points[0].NetChange)
	}
	if tr.Points[1].NetChange != 5 {
		t.Errorf("day two shrank: want 5, got %d", tr.Points[1].NetChange)
	}
	// The serialised value must agree with the method it replaced being unused, not drift from it.
	for _, p := range tr.Points {
		if p.NetChange != p.Net() {
			t.Errorf("NetChange (%d) disagrees with Net() (%d)", p.NetChange, p.Net())
		}
	}
}
