package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// EventPoller reads every entitled tenant's event sources (CloudTrail, identity-provider audit logs) on a
// short interval, so an incident opens minutes after the event rather than at the next full pass.
//
// Same entitlement gate as the full Scheduler: continuous monitoring is the paid capability, and this is
// part of it. Separate from Scheduler because the two have different costs — a full pass spawns a sandbox
// scan per asset, an event poll is a handful of read calls — so they deserve different clocks.
type EventPoller struct {
	Store    store.Store
	Runner   *runner.Service
	Interval time.Duration
	Log      *log.Logger // optional
}

func (p *EventPoller) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Tick polls every entitled tenant once. Returns how many incidents were opened.
func (p *EventPoller) Tick(ctx context.Context) (int, error) {
	tenants, err := p.Store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	opened := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return opened, ctx.Err()
		}
		if !platform.Entitlements(t.Plan).ContinuousMonitoring {
			continue
		}
		opened += p.Runner.PollEvents(ctx, t.ID).Opened
	}
	return opened, nil
}

// Run polls on Interval until ctx is cancelled. A zero/negative Interval disables it — the full pass
// still reads the event sources, on its own slower clock.
func (p *EventPoller) Run(ctx context.Context) error {
	if p.Interval <= 0 {
		p.logf("[events] fast event polling disabled; event sources are read on the full monitoring pass only")
		return nil
	}
	p.logf("[events] polling CloudTrail and identity-provider logs every %s", p.Interval)
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if n, err := p.Tick(ctx); err != nil && ctx.Err() == nil {
				p.logf("[events] poll error: %v", err)
			} else if n > 0 {
				p.logf("[events] %d incident(s) opened from event sources", n)
			}
		}
	}
}
