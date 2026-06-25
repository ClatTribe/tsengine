package scheduler

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
)

// CorpusRefresher keeps the GLOBAL threat-intel corpus (KEV/EPSS) fresh on an in-process clock, so the
// platform's "continuously updating" intel doesn't depend on an external ops cron. It is the GLOBAL
// twin of Scheduler: Scheduler is the per-TENANT clock (re-scan each tenant); CorpusRefresher is the
// one-SHARED-corpus clock (refresh the world-state reference intel every tenant's findings enrich
// against). The refreshed file is picked up by the next scan's threat_intel.enrich hook, which re-reads
// TSENGINE_THREAT_INTEL_CORPUS per scan. Best-effort: a failed fetch keeps the last good corpus and
// never blocks scanning (CLAUDE.md §7 — OSINT-fresh yet pinned-per-scan, not a live per-query call).
type CorpusRefresher struct {
	// DataPath is the corpus data file (TSENGINE_THREAT_INTEL_CORPUS, e.g. /data/corpus/threat_intel.json).
	// Refresh writes <dir>/threat_intel.json into its parent dir.
	DataPath string
	Interval time.Duration // refresh cadence; <=0 disables
	// Refresh is injectable for tests; nil → the live threatintel.Refresh into DataPath's dir.
	Refresh func(ctx context.Context, dir string) (threatintel.Manifest, error)
	Log     *log.Logger
}

func (c *CorpusRefresher) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (c *CorpusRefresher) doRefresh(ctx context.Context) (threatintel.Manifest, error) {
	dir := filepath.Dir(c.DataPath)
	if c.Refresh != nil {
		return c.Refresh(ctx, dir)
	}
	m, _, err := threatintel.Refresh(ctx, threatintel.RefreshOptions{OutDir: dir})
	return m, err
}

// fresh reports whether the on-disk corpus is younger than Interval — so a platform restart doesn't
// re-fetch a corpus that's already current (the feeds update at most daily).
func (c *CorpusRefresher) fresh(now time.Time) bool {
	m, err := threatintel.LoadManifest(c.DataPath)
	if err != nil {
		return false // no/unreadable manifest → treat as stale, refresh
	}
	return !m.BuiltAt.IsZero() && now.Sub(m.BuiltAt) < c.Interval
}

// Tick runs one refresh. Best-effort: a failure is logged and the last good corpus is kept.
func (c *CorpusRefresher) Tick(ctx context.Context) {
	m, err := c.doRefresh(ctx)
	if err != nil {
		if ctx.Err() == nil {
			c.logf("[corpus] threat-intel refresh failed (keeping last good corpus): %v", err)
		}
		return
	}
	c.logf("[corpus] threat-intel refreshed: %s — %d CVEs (%d KEV, %d EPSS)", m.Version, m.EntryCount, m.KEVCount, m.EPSSCount)
}

// Run refreshes the global corpus on Interval until ctx is cancelled. It refreshes once at start ONLY
// if the on-disk corpus is stale (older than Interval / missing), then every Interval. A zero/negative
// Interval — or an empty DataPath (TSENGINE_THREAT_INTEL_CORPUS unset, so the engine uses its embedded
// snapshot) — disables the loop.
func (c *CorpusRefresher) Run(ctx context.Context) error {
	if c.Interval <= 0 {
		c.logf("[corpus] auto-refresh disabled (interval <= 0)")
		return nil
	}
	if c.DataPath == "" {
		c.logf("[corpus] auto-refresh disabled (TSENGINE_THREAT_INTEL_CORPUS unset; using embedded snapshot)")
		return nil
	}
	c.logf("[corpus] global threat-intel auto-refresh every %s → %s", c.Interval, c.DataPath)
	if !c.fresh(time.Now()) {
		c.Tick(ctx) // stale or missing at boot → refresh now
	} else {
		c.logf("[corpus] on-disk corpus is current; next refresh in %s", c.Interval)
	}
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.Tick(ctx)
		}
	}
}
