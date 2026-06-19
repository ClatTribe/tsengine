package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func newIDFn() func() string {
	var n int64
	return func() string { return fmt.Sprintf("job-%d", atomic.AddInt64(&n, 1)) }
}

func waitFor(t *testing.T, p *Pool, id string, want Status) Job {
	t.Helper()
	for i := 0; i < 200; i++ {
		if j, ok := p.Get(id); ok && j.Status == want {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	j, _ := p.Get(id)
	t.Fatalf("job %s never reached %s (last=%s err=%q)", id, want, j.Status, j.Error)
	return Job{}
}

func TestPool_RunsAndReportsResult(t *testing.T) {
	p := NewPool(2, 8, 100, time.Minute, newIDFn())
	defer func() { _ = p.Shutdown(context.Background()) }()

	j, err := p.Enqueue("test", "t1", func(context.Context) (any, error) { return "ok", nil })
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != StatusQueued {
		t.Errorf("fresh job should be queued, got %s", j.Status)
	}
	done := waitFor(t, p, j.ID, StatusDone)
	if done.Result != "ok" || done.FinishedAt.IsZero() {
		t.Errorf("bad terminal job: %+v", done)
	}
}

func TestPool_ErrorAndPanicBecomeFailed(t *testing.T) {
	p := NewPool(1, 8, 100, time.Minute, newIDFn())
	defer func() { _ = p.Shutdown(context.Background()) }()

	bad, _ := p.Enqueue("test", "t1", func(context.Context) (any, error) { return nil, errors.New("boom") })
	if j := waitFor(t, p, bad.ID, StatusFailed); j.Error != "boom" {
		t.Errorf("want error 'boom', got %q", j.Error)
	}
	// a panicking job must not take the worker down — it fails and the pool keeps working.
	pan, _ := p.Enqueue("test", "t1", func(context.Context) (any, error) { panic("kaboom") })
	waitFor(t, p, pan.ID, StatusFailed)
	ok, _ := p.Enqueue("test", "t1", func(context.Context) (any, error) { return 1, nil })
	waitFor(t, p, ok.ID, StatusDone) // pool still alive
}

func TestPool_ListIsTenantScoped(t *testing.T) {
	p := NewPool(2, 8, 100, time.Minute, newIDFn())
	defer func() { _ = p.Shutdown(context.Background()) }()
	a, _ := p.Enqueue("test", "tenant-a", func(context.Context) (any, error) { return nil, nil })
	_, _ = p.Enqueue("test", "tenant-b", func(context.Context) (any, error) { return nil, nil })
	waitFor(t, p, a.ID, StatusDone)

	la := p.List("tenant-a")
	if len(la) != 1 || la[0].TenantID != "tenant-a" {
		t.Fatalf("tenant-a should see only its own job, got %+v", la)
	}
}

func TestPool_BusyWhenQueueFull(t *testing.T) {
	// 1 worker, queue size 1; block the worker so the queue fills.
	release := make(chan struct{})
	p := NewPool(1, 1, 100, time.Minute, newIDFn())
	defer func() { close(release); _ = p.Shutdown(context.Background()) }()

	if _, err := p.Enqueue("test", "t1", func(context.Context) (any, error) { <-release; return nil, nil }); err != nil {
		t.Fatal(err) // occupies the worker
	}
	time.Sleep(20 * time.Millisecond)
	_, _ = p.Enqueue("test", "t1", func(context.Context) (any, error) { return nil, nil }) // fills the queue
	// next one must be rejected with ErrBusy
	if _, err := p.Enqueue("test", "t1", func(context.Context) (any, error) { return nil, nil }); !errors.Is(err, ErrBusy) {
		t.Errorf("want ErrBusy when full, got %v", err)
	}
}
