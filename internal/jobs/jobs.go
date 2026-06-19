// Package jobs runs background work off the request path. The platform's rescans used to
// run synchronously inside the HTTP handler — a long scan blocked the request and held the
// goroutine. A Pool accepts a unit of work, returns immediately with a Job the caller can
// poll, and runs it on a bounded worker pool.
//
// This is the single-box implementation: an in-process pool with a bounded queue (back-
// pressure when full) and in-memory job state. It sits behind a small surface (Enqueue /
// Get / List) so scaling out later is a swap for a real durable queue (Redis/SQS) — the
// callers don't change. Job state is ephemeral (lost on restart), which is fine: a job is
// a transient "is this scan done yet", not a system of record (findings/incidents persist
// in the store).
package jobs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Status is a job's lifecycle state.
type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
)

// ErrBusy is returned by Enqueue when the queue is full (back-pressure).
var ErrBusy = errors.New("jobs: queue is full, try again shortly")

// Job is a unit of background work and its result. Tenant-scoped so callers can enforce
// isolation on Get/List.
type Job struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Kind       string    `json:"kind"`
	Status     Status    `json:"status"`
	Error      string    `json:"error,omitempty"`
	Result     any       `json:"result,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// Func is the work a job runs. Its return value becomes Job.Result; its error → Job.Error.
type Func func(context.Context) (any, error)

type task struct {
	job *Job
	fn  Func
}

// Pool is a bounded in-process worker pool.
type Pool struct {
	mu      sync.RWMutex
	jobs    map[string]*Job
	order   []string // job ids oldest→newest, for retention pruning
	ch      chan task
	newID   func() string
	timeout time.Duration
	retain  int
	wg      sync.WaitGroup
	closed  bool
}

// NewPool starts `workers` goroutines draining a queue of `queueSize`. Each job runs with
// `timeout`. At most `retain` finished jobs are kept (oldest pruned). newID mints job ids.
func NewPool(workers, queueSize, retain int, timeout time.Duration, newID func() string) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	if retain < 1 {
		retain = 1000
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	p := &Pool{jobs: map[string]*Job{}, ch: make(chan task, queueSize), newID: newID, timeout: timeout, retain: retain}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for t := range p.ch {
		now := time.Now().UTC()
		p.update(t.job.ID, func(j *Job) { j.Status = StatusRunning; j.StartedAt = now })
		res, err := run(p.timeout, t.fn)
		p.update(t.job.ID, func(j *Job) {
			j.FinishedAt = time.Now().UTC()
			if err != nil {
				j.Status = StatusFailed
				j.Error = err.Error()
			} else {
				j.Status = StatusDone
				j.Result = res
			}
		})
	}
}

// run executes fn with a timeout, converting a panic into an error (a panicking job must
// not take the worker down).
func run(timeout time.Duration, fn Func) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("job panicked: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return fn(ctx)
}

// Enqueue records a job and submits it, returning immediately. ErrBusy if the queue is full.
func (p *Pool) Enqueue(kind, tenantID string, fn Func) (Job, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return Job{}, errors.New("jobs: pool is shutting down")
	}
	j := &Job{ID: p.newID(), TenantID: tenantID, Kind: kind, Status: StatusQueued, CreatedAt: time.Now().UTC()}
	select {
	case p.ch <- task{job: j, fn: fn}:
		// Record under the same lock the worker needs to mark it Running, so the worker
		// can never observe a job that isn't yet in the map.
		p.jobs[j.ID] = j
		p.order = append(p.order, j.ID)
		p.prune()
		return *j, nil
	default:
		return Job{}, ErrBusy
	}
}

func (p *Pool) update(id string, f func(*Job)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if j := p.jobs[id]; j != nil {
		f(j)
	}
}

// Inflight is the number of jobs currently queued or running — the operational signal
// for whether scans are backing up (exposed as a Prometheus gauge by the platform).
func (p *Pool) Inflight() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, id := range p.order {
		if j := p.jobs[id]; j != nil && (j.Status == StatusQueued || j.Status == StatusRunning) {
			n++
		}
	}
	return n
}

// Get returns a copy of the job, or false if unknown.
func (p *Pool) Get(id string) (Job, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if j := p.jobs[id]; j != nil {
		return *j, true
	}
	return Job{}, false
}

// List returns a tenant's jobs, newest first.
func (p *Pool) List(tenantID string) []Job {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []Job
	for _, id := range p.order {
		if j := p.jobs[id]; j != nil && j.TenantID == tenantID {
			out = append(out, *j)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].CreatedAt.After(out[k].CreatedAt) })
	return out
}

// prune drops the oldest finished jobs over the retention cap. Caller holds the lock.
func (p *Pool) prune() {
	for len(p.order) > p.retain {
		oldest := p.order[0]
		if j := p.jobs[oldest]; j != nil && (j.Status == StatusQueued || j.Status == StatusRunning) {
			return // never evict an in-flight job; stop pruning this round
		}
		p.order = p.order[1:]
		delete(p.jobs, oldest)
	}
}

// Shutdown stops accepting work and waits for in-flight jobs to finish (or ctx to expire).
func (p *Pool) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	p.mu.Unlock()
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
