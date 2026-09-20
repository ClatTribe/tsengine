package rlvr

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/ClatTribe/tsengine/internal/pentest"
)

// prober.go turns a LIVE probe run into an OFFLINE, replayable corpus. Grading is only a
// bootstrap if the (attempt → real outcome) episodes accumulate at ~$0 and re-grade
// deterministically in CI — but a live target (a vulhub container) is not in CI, and re-probing
// it every train step is neither cheap nor reproducible (the container's state drifts). So a live
// run is RECORDED once and REPLAYED forever: the recorded responses are the fixed bytes the
// predicate disposes over, exactly the property that makes the reward ungameable.
//
// The Recorder wraps any Prober (pentest.HTTPProber against a real target, or a fake in tests);
// the Replayer serves the captured responses back with no network. A live run captures; every
// subsequent grade — including the RLVR train loop's thousands of re-scorings of the same episode
// — replays.

// probeKey is the canonical, order-stable identity of a probe: method + URL + body + sorted
// headers. Two probes with the same key must get the same recorded response, so the key must not
// depend on Go map iteration order (headers are a map). JSON of a normalized shape gives that.
func probeKey(p pentest.Probe) string {
	hdr := make([][2]string, 0, len(p.Headers))
	for k, v := range p.Headers {
		hdr = append(hdr, [2]string{k, v})
	}
	sort.Slice(hdr, func(i, j int) bool { return hdr[i][0] < hdr[j][0] })
	b, _ := json.Marshal(struct {
		M string      `json:"m"`
		U string      `json:"u"`
		B string      `json:"b"`
		H [][2]string `json:"h"`
	}{p.Method, p.URL, p.Body, hdr})
	return string(b)
}

// Recorder wraps a live Prober and captures every (probe → result) into an ordered log. It is
// pass-through: Send delegates, records the outcome, and returns it unchanged, so a recorded run
// is byte-identical to an unrecorded one. A transport ERROR is recorded too (as an Entry with
// Err set) so a replay reproduces the SAME Ungradeable verdict the live run produced — otherwise
// replaying a corpus would silently turn an unreachable target into a gradeable one, the exact
// drop-hiding failure §10 forbids.
type Recorder struct {
	Inner pentest.Prober
	mu    sync.Mutex
	log   []Entry
	seen  map[string]int // probeKey → index in log (last write wins on a repeat)
}

// Entry is one recorded probe outcome.
type Entry struct {
	Key    string              `json:"key"`
	Result pentest.ProbeResult `json:"result"`
	Err    string              `json:"err,omitempty"` // non-empty ⇒ the live probe failed transport
}

// NewRecorder wraps a live prober for capture.
func NewRecorder(inner pentest.Prober) *Recorder {
	return &Recorder{Inner: inner, seen: map[string]int{}}
}

// Send delegates to the inner prober and records the outcome (result or error) before returning
// it unchanged.
func (r *Recorder) Send(ctx context.Context, p pentest.Probe) (pentest.ProbeResult, error) {
	res, err := r.Inner.Send(ctx, p)
	r.mu.Lock()
	defer r.mu.Unlock()
	e := Entry{Key: probeKey(p), Result: res}
	if err != nil {
		e.Err = err.Error()
	}
	if idx, ok := r.seen[e.Key]; ok {
		r.log[idx] = e // last observation wins — a target that changed mid-run replays its final state
	} else {
		r.seen[e.Key] = len(r.log)
		r.log = append(r.log, e)
	}
	return res, err
}

// Cassette is the serialized recording — a self-contained corpus of probe outcomes that replays
// with no target. It is the artifact a live run produces and CI consumes.
type Cassette struct {
	Entries []Entry `json:"entries"`
}

// Cassette snapshots what the recorder has captured so far.
func (r *Recorder) Cassette() Cassette {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Entry, len(r.log))
	copy(out, r.log)
	return Cassette{Entries: out}
}

// errReplayMiss is a permanent (non-transient) transport-shaped error for a probe absent from the
// cassette. It surfaces as Ungradeable, NOT NotExploited: a probe we never recorded is a gap in
// the corpus, not a proof the target is clean. A replay that invented a 404 for a missing probe
// could flip a real exploit to a false negative.
type errReplayMiss struct{ key string }

func (e errReplayMiss) Error() string {
	return fmt.Sprintf("rlvr replay: probe not in cassette: %s", e.key)
}

// Replayer serves recorded responses with no network — the CI/train-time Prober. A probe present
// in the cassette returns its recorded (result, err); a probe absent returns errReplayMiss →
// Ungradeable, so a corpus gap can never masquerade as a graded negative.
type Replayer struct {
	byKey map[string]Entry
}

// NewReplayer builds a replay prober from a cassette.
func NewReplayer(c Cassette) *Replayer {
	m := make(map[string]Entry, len(c.Entries))
	for _, e := range c.Entries {
		m[e.Key] = e
	}
	return &Replayer{byKey: m}
}

// Send serves the recorded outcome for the probe, or errReplayMiss if it was never recorded.
func (rp *Replayer) Send(_ context.Context, p pentest.Probe) (pentest.ProbeResult, error) {
	e, ok := rp.byKey[probeKey(p)]
	if !ok {
		return pentest.ProbeResult{}, errReplayMiss{key: probeKey(p)}
	}
	if e.Err != "" {
		// Reproduce the live transport failure so the verdict stays Ungradeable on replay.
		return pentest.ProbeResult{}, errReplayMiss{key: e.Key}
	}
	return e.Result, nil
}

// interface assertions
var (
	_ pentest.Prober = (*Recorder)(nil)
	_ pentest.Prober = (*Replayer)(nil)
)
