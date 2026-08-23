// Package detectionvalidation answers the question that defines this product category: when we
// proved an attack works, did the customer's own defences notice?
//
// tsengine proves exploitability and proves closure. It never asked whether the EDR, WAF or SIEM the
// customer already pays for saw any of it — which is the test Gartner's 2026 AEV guidance uses to
// define the category (ADR 0027).
//
// # THE INVARIANT: silence is not a miss
//
// The tempting implementation reports "no matching alert" as "your control missed it". That is a
// false accusation about someone else's product, made from our own blind spot, and silence has at
// least four causes: the sensor is not deployed, telemetry has not arrived yet, our correlation
// window is wrong, or it genuinely missed.
//
// So a MISS is only ever claimed when the pipeline is demonstrably alive — the same sensor reported
// something else in the same window, which proves it was watching and talking to us. Otherwise the
// answer is Undetermined, which is §10's "we could not look" in this package's vocabulary. The
// distinction is the whole reason this is worth building rather than a chart that always has an
// answer.
//
// # Two strengths of evidence, never merged
//
// A sensor that captured our canary in the request is an EXACT tie between one alert and one probe.
// A sensor that merely reported an attack of the same class against the same endpoint inside the
// window is an INFERENCE — right most of the time, and wrong exactly when a real attacker is hitting
// the same endpoint concurrently, which is the moment it matters most. Both are reported; they are
// never collapsed into one confidence.
package detectionvalidation

import (
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Verdict for one probe.
const (
	// Detected: a runtime event ties back to this probe.
	Detected = "detected"
	// NotDetected: nothing tied back, AND the sensor demonstrably had its eyes open — it reported
	// something else in the same window. This is the only state that accuses a control of missing.
	NotDetected = "not_detected"
	// Undetermined: nothing tied back and we cannot show the pipeline was working. Never a miss.
	Undetermined = "undetermined"
)

// Evidence strength, kept apart on purpose (see the package comment).
const (
	// StrengthMarker: the sensor reported the probe's own canary. Exact.
	StrengthMarker = "marker"
	// StrengthCorrelated: same endpoint, same attack class, inside the window. An inference.
	StrengthCorrelated = "correlated"
)

// Probe is one thing we fired, from the engagement's recorded attempts.
type Probe struct {
	Canary  string
	Target  string
	Class   string // the attack class, matched against RuntimeEvent.AttackKind
	FiredAt time.Time
	Proven  bool
}

// Result is what the customer's controls did about it.
type Result struct {
	Canary   string `json:"canary"`
	Target   string `json:"target"`
	Verdict  string `json:"verdict"`
	Strength string `json:"strength,omitempty"`
	// Blocked reports that the sensor STOPPED it rather than merely recording it. A control in
	// monitor-only mode is a materially different answer from one that intervened, and rendering
	// them alike would let "we saw it" pass for "we stopped it".
	Blocked bool   `json:"blocked,omitempty"`
	Why     string `json:"why,omitempty"`
	EventID string `json:"event_id,omitempty"`
}

// Report is the estate-wide answer.
type Report struct {
	Results      []Result `json:"results"`
	Detected     int      `json:"detected"`
	NotDetected  int      `json:"not_detected"`
	Undetermined int      `json:"undetermined"`
	// Blocked counts detections where a control intervened rather than observed.
	Blocked int    `json:"blocked"`
	Caveat  string `json:"caveat"`
}

const caveat = "A probe with no matching alert is only reported as a MISS when the sensor proved it " +
	"was watching — it reported something else in the same window. Otherwise the answer is " +
	"undetermined: an undeployed sensor, late telemetry and a genuine miss look identical from here, " +
	"and calling that a miss would accuse a control we could not observe."

// DefaultWindow is how long after a probe an alert may still be attributed to it.
const DefaultWindow = 10 * time.Minute

// Validate correlates probes against the sensor events a tenant's runtime reported.
func Validate(probes []Probe, events []platform.RuntimeEvent, window time.Duration) Report {
	if window <= 0 {
		window = DefaultWindow
	}
	rep := Report{Caveat: caveat}
	for _, p := range probes {
		if strings.TrimSpace(p.Canary) == "" {
			continue // nothing to join on; never guessed at (§10)
		}
		r := Result{Canary: p.Canary, Target: p.Target}
		var alive bool
		var best *platform.RuntimeEvent
		var bestStrength string

		for i := range events {
			e := events[i]
			within := !e.OccurredAt.Before(p.FiredAt) && e.OccurredAt.Sub(p.FiredAt) <= window
			if within {
				alive = true // the sensor was talking to us in this window, whatever it said
			}
			switch {
			case e.Marker != "" && e.Marker == p.Canary:
				// Exact, and it wins regardless of the window: the sensor saw OUR token.
				best, bestStrength = &events[i], StrengthMarker
			case within && bestStrength != StrengthMarker && sameTarget(e.Endpoint, p.Target) &&
				sameClass(e.AttackKind, p.Class):
				best, bestStrength = &events[i], StrengthCorrelated
			}
		}

		switch {
		case best != nil:
			r.Verdict, r.Strength, r.Blocked, r.EventID = Detected, bestStrength, best.Blocked, best.ID
			if bestStrength == StrengthCorrelated {
				r.Why = "matched by endpoint, attack class and timing — an inference, not the sensor " +
					"reporting our own token"
			}
			rep.Detected++
			if best.Blocked {
				rep.Blocked++
			}
		case alive:
			r.Verdict = NotDetected
			r.Why = "the sensor reported other activity in this window, so it was watching and did " +
				"not report this"
			rep.NotDetected++
		default:
			r.Verdict = Undetermined
			r.Why = "no sensor telemetry at all in this window — an undeployed sensor, late telemetry " +
				"and a genuine miss are indistinguishable from here"
			rep.Undetermined++
		}
		rep.Results = append(rep.Results, r)
	}
	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Canary < rep.Results[j].Canary })
	return rep
}

// ProbesFrom lifts the recorded attempts of an engagement into probes. Only attempts the RoE ALLOWED
// are probes: a denied one never left the building, so a control cannot be faulted for not seeing it.
func ProbesFrom(attempts []pentest.AttemptRecord) []Probe {
	var out []Probe
	for _, a := range attempts {
		if !a.Allowed || strings.TrimSpace(a.Canary) == "" {
			continue
		}
		out = append(out, Probe{Canary: a.Canary, Target: a.Target, Class: a.Method,
			FiredAt: a.At, Proven: a.Proven})
	}
	return out
}

func sameTarget(endpoint, target string) bool {
	e, t := strings.TrimSpace(strings.ToLower(endpoint)), strings.TrimSpace(strings.ToLower(target))
	if e == "" || t == "" {
		return false // never match on emptiness
	}
	return e == t || strings.Contains(t, e) || strings.Contains(e, t)
}

func sameClass(kind, class string) bool {
	k, c := strings.ToLower(strings.TrimSpace(kind)), strings.ToLower(strings.TrimSpace(class))
	if k == "" || c == "" {
		return false
	}
	return k == c || strings.Contains(c, k) || strings.Contains(k, c)
}
