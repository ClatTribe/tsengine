// Package scheduler is the platform's continuous-monitoring loop (the "autonomous" in
// autonomous security team): on a fixed cadence it re-scans every tenant's assets, so
// posture and findings stay current without a human or a webhook. Event-driven re-scans
// (a GitHub push) still flow through the runner's OnTrigger; the scheduler is the
// baseline heartbeat that catches drift and the non-webhook (scheduled-posture) assets.
package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
)

// Scheduler re-scans every tenant on Interval.
type Scheduler struct {
	Store    store.Store
	Runner   *runner.Service
	Interval time.Duration
	Log      *log.Logger // optional
}

func (s *Scheduler) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Tick runs one full pass: re-scan every tenant's assets. Returns the number of
// (tenant, asset) scans completed. Exposed so the loop is testable without a real timer.
func (s *Scheduler) Tick(ctx context.Context) (int, error) {
	tenants, err := s.Store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, rerr := s.Runner.RescanTenant(ctx, t.ID)
		total += n
		if rerr != nil {
			s.logf("[scheduler] tenant %s: %v (scanned %d)", t.ID, rerr, n)
		}
	}
	return total, nil
}

// Run loops Tick on Interval until ctx is cancelled. It fires once immediately, then
// every Interval. A zero/negative Interval disables the loop (returns nil).
func (s *Scheduler) Run(ctx context.Context) error {
	if s.Interval <= 0 {
		s.logf("[scheduler] disabled (interval <= 0)")
		return nil
	}
	s.logf("[scheduler] continuous monitoring every %s", s.Interval)
	tick := func() {
		n, err := s.Tick(ctx)
		if err != nil && ctx.Err() == nil {
			s.logf("[scheduler] tick error: %v", err)
		} else {
			s.logf("[scheduler] tick: %d scan(s)", n)
		}
	}
	tick() // fire once at start
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			tick()
		}
	}
}
