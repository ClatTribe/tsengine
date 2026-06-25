package scheduler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
)

func TestCorpusRefresher_TickBestEffortOnError(t *testing.T) {
	called := 0
	c := &CorpusRefresher{
		DataPath: "/tmp/corpus/threat_intel.json",
		Interval: time.Hour,
		Refresh: func(_ context.Context, dir string) (threatintel.Manifest, error) {
			called++
			if dir != "/tmp/corpus" {
				t.Errorf("refresh should target the data file's dir, got %q", dir)
			}
			return threatintel.Manifest{}, errors.New("feed down")
		},
	}
	c.Tick(context.Background()) // must not panic / must swallow the error (last good corpus kept)
	if called != 1 {
		t.Fatalf("Tick should call refresh once, got %d", called)
	}
}

func TestCorpusRefresher_DisabledGuards(t *testing.T) {
	// interval <= 0 disables — Run returns immediately without refreshing.
	got := 0
	c := &CorpusRefresher{DataPath: "/x/threat_intel.json", Interval: 0,
		Refresh: func(context.Context, string) (threatintel.Manifest, error) { got++; return threatintel.Manifest{}, nil }}
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("disabled Run should return nil, got %v", err)
	}
	// empty DataPath also disables (engine falls back to the embedded snapshot).
	c2 := &CorpusRefresher{DataPath: "", Interval: time.Hour,
		Refresh: func(context.Context, string) (threatintel.Manifest, error) { got++; return threatintel.Manifest{}, nil }}
	if err := c2.Run(context.Background()); err != nil {
		t.Fatalf("no-path Run should return nil, got %v", err)
	}
	if got != 0 {
		t.Fatalf("disabled refreshers must not fetch, fetched %d", got)
	}
}

func TestCorpusRefresher_FreshSkipsInitialFetch(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, threatintel.DataFileName)
	// Write a manifest built 1 minute ago — within a 24h interval, so it's "fresh".
	if _, err := threatintel.Write(dir, map[string]threatintel.Entry{},
		threatintel.Manifest{Version: "t", BuiltAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	c := &CorpusRefresher{DataPath: data, Interval: 24 * time.Hour}
	if !c.fresh(time.Now()) {
		t.Error("a corpus built a minute ago should be fresh under a 24h interval")
	}
	// An older-than-interval manifest is stale.
	if _, err := threatintel.Write(dir, map[string]threatintel.Entry{},
		threatintel.Manifest{Version: "t", BuiltAt: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if c.fresh(time.Now()) {
		t.Error("a corpus built 48h ago should be stale under a 24h interval")
	}
	// Missing manifest → stale (refresh).
	c.DataPath = filepath.Join(dir, "nope.json")
	if c.fresh(time.Now()) {
		t.Error("a missing corpus should be treated as stale")
	}
}
