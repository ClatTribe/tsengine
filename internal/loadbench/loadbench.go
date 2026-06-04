// Package loadbench is a load + correctness benchmark for the tsengine HTTP
// service (`tsengine serve`). It is NOT just a throughput meter: alongside latency
// percentiles and req/s it asserts a SECURITY invariant under concurrency — every
// unauthenticated /replay must be rejected and every authenticated one must pass
// the auth gate, with ZERO violations across thousands of racing requests. A pure
// speed test would miss an auth-bypass race; this is the benchmark you run before
// putting the service in front of a customer.
package loadbench

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config bounds a run.
type Config struct {
	BaseURL     string        // e.g. http://127.0.0.1:8080
	Token       string        // the service's bearer token
	Requests    int           // total HTTP requests (ignored if Duration > 0)
	Duration    time.Duration // if > 0, run for this long instead of a fixed count
	Concurrency int           // parallel workers
	Client      *http.Client
}

func (c *Config) defaults() {
	if c.Concurrency <= 0 {
		c.Concurrency = 16
	}
	if c.Requests <= 0 && c.Duration <= 0 {
		c.Requests = 3000
	}
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 10 * time.Second}
	}
}

// kind is one request type in the standard service mix.
type kind struct {
	method    string
	path      string
	withToken bool
	wantAuth  bool // true: auth must PASS (status != 401); false (replay_noauth): auth must HOLD (status == 401)
	authProbe bool // contributes to the security invariant
}

// the standard mix: liveness + replay-without-token (must 401) + replay-with-token
// (must pass auth). Two of every three requests probe the auth gate.
var mix = []kind{
	{http.MethodGet, "/healthz", false, false, false},
	{http.MethodPost, "/replay", false, false, true},
	{http.MethodPost, "/replay", true, true, true},
}

const replayBody = `{"scan_id":"loadbench-nonexistent","tool":"nuclei"}`

type sample struct {
	latency   time.Duration
	status    int
	failed    bool // transport error
	authProbe bool // request contributed to the security invariant
	violation bool // security invariant broken
}

// Result is the scorecard.
type Result struct {
	Requests       int           `json:"requests"`
	Concurrency    int           `json:"concurrency"`
	Wall           time.Duration `json:"wall"`
	Throughput     float64       `json:"throughput_rps"`
	Mean           time.Duration `json:"mean"`
	P50            time.Duration `json:"p50"`
	P95            time.Duration `json:"p95"`
	P99            time.Duration `json:"p99"`
	Max            time.Duration `json:"max"`
	Errors         int           `json:"transport_errors"`
	Status         map[int]int   `json:"status_counts"`
	AuthProbes     int           `json:"auth_probes"`
	AuthViolations int           `json:"auth_violations"` // MUST be 0
	Pass           bool          `json:"pass"`
}

// Run drives the standard mix (health + replay-without-token + replay-with-token)
// at the configured concurrency and returns the scorecard.
func Run(ctx context.Context, cfg Config) (Result, error) {
	cfg.defaults()
	base := strings.TrimRight(cfg.BaseURL, "/")

	var counter int64
	deadline := time.Time{}
	if cfg.Duration > 0 {
		deadline = time.Now().Add(cfg.Duration)
	}

	perWorker := make([][]sample, cfg.Concurrency)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var local []sample
			for {
				if ctx.Err() != nil {
					break
				}
				i := atomic.AddInt64(&counter, 1) - 1
				if cfg.Duration > 0 {
					if time.Now().After(deadline) {
						break
					}
				} else if i >= int64(cfg.Requests) {
					break
				}
				local = append(local, fire(ctx, cfg.Client, base, cfg.Token, mix[i%int64(len(mix))]))
			}
			perWorker[w] = local
		}(w)
	}
	wg.Wait()
	wall := time.Since(start)

	return summarize(perWorker, wall, cfg.Concurrency), nil
}

func fire(ctx context.Context, client *http.Client, base, token string, k kind) sample {
	var body io.Reader
	if k.method == http.MethodPost {
		body = strings.NewReader(replayBody)
	}
	req, err := http.NewRequestWithContext(ctx, k.method, base+k.path, body)
	if err != nil {
		return sample{failed: true}
	}
	if k.withToken {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	t0 := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(t0)
	if err != nil {
		return sample{latency: lat, failed: true}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	s := sample{latency: lat, status: resp.StatusCode, authProbe: k.authProbe}
	if k.authProbe {
		if k.wantAuth {
			// auth must PASS: a 401 here means a valid token was rejected.
			s.violation = resp.StatusCode == http.StatusUnauthorized
		} else {
			// auth must HOLD: anything but 401 means an unauthenticated request got through.
			s.violation = resp.StatusCode != http.StatusUnauthorized
		}
	}
	return s
}

func summarize(perWorker [][]sample, wall time.Duration, concurrency int) Result {
	r := Result{Concurrency: concurrency, Wall: wall, Status: map[int]int{}}
	var lat []time.Duration
	var sum time.Duration
	for _, ws := range perWorker {
		for _, s := range ws {
			r.Requests++
			if s.failed {
				r.Errors++
				continue
			}
			r.Status[s.status]++
			lat = append(lat, s.latency)
			sum += s.latency
			if s.authProbe {
				r.AuthProbes++
			}
			if s.violation {
				r.AuthViolations++
			}
		}
	}

	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		r.Mean = sum / time.Duration(len(lat))
		r.P50 = pct(lat, 50)
		r.P95 = pct(lat, 95)
		r.P99 = pct(lat, 99)
		r.Max = lat[len(lat)-1]
	}
	if wall > 0 {
		r.Throughput = float64(r.Requests-r.Errors) / wall.Seconds()
	}
	r.Pass = r.AuthViolations == 0 && r.Errors == 0
	return r
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// Render formats the scorecard.
func Render(r Result) string {
	var b strings.Builder
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "=== tsengine serve — load + correctness benchmark ===\n")
	fmt.Fprintf(&b, "requests=%d  concurrency=%d  wall=%s  throughput=%.0f req/s  verdict=%s\n",
		r.Requests, r.Concurrency, r.Wall.Round(time.Millisecond), r.Throughput, verdict)
	fmt.Fprintf(&b, "latency: mean=%s  p50=%s  p95=%s  p99=%s  max=%s\n",
		r.Mean.Round(time.Microsecond), r.P50.Round(time.Microsecond), r.P95.Round(time.Microsecond),
		r.P99.Round(time.Microsecond), r.Max.Round(time.Microsecond))
	fmt.Fprintf(&b, "transport errors: %d\n", r.Errors)
	fmt.Fprintf(&b, "status mix: %s\n", statusLine(r.Status))
	fmt.Fprintf(&b, "AUTH INVARIANT: %d violations across %d probes  (%s)\n",
		r.AuthViolations, r.AuthProbes, invariantNote(r.AuthViolations))
	return b.String()
}

func statusLine(m map[int]int) string {
	var codes []int
	for c := range m {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	var parts []string
	for _, c := range codes {
		parts = append(parts, fmt.Sprintf("%d×%d", c, m[c]))
	}
	return strings.Join(parts, "  ")
}

func invariantNote(violations int) string {
	if violations == 0 {
		return "auth gate held under load ✓"
	}
	return "AUTH BYPASS / FALSE-REJECT UNDER LOAD ✗"
}
