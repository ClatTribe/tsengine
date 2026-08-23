package detectionvalidation_test

import (
	"strings"
	"testing"
	"time"

	dv "github.com/ClatTribe/tsengine/internal/detectionvalidation"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

var t0 = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func probe(canary string) dv.Probe {
	return dv.Probe{Canary: canary, Target: "https://app/search", Class: "sql_injection", FiredAt: t0}
}

func event(id string, at time.Time, mut func(*platform.RuntimeEvent)) platform.RuntimeEvent {
	e := platform.RuntimeEvent{ID: id, AttackKind: "sql_injection", Endpoint: "https://app/search", OccurredAt: at}
	if mut != nil {
		mut(&e)
	}
	return e
}

// THE INVARIANT. Silence is not a miss. An undeployed sensor, late telemetry and a genuine miss are
// indistinguishable from here, and reporting silence as "your control missed it" is a false
// accusation about someone else's product made from our own blind spot.
func TestValidate_SilenceIsUndeterminedNotAMiss(t *testing.T) {
	r := dv.Validate([]dv.Probe{probe("c1")}, nil, 0)
	if len(r.Results) != 1 || r.Results[0].Verdict != dv.Undetermined {
		t.Fatalf("no telemetry at all must be undetermined, got %+v", r.Results)
	}
	if r.NotDetected != 0 {
		t.Error("nothing may be counted as a miss when the sensor was never heard from")
	}
	if !strings.Contains(r.Results[0].Why, "indistinguishable") {
		t.Errorf("the reason must say why we cannot tell, got: %s", r.Results[0].Why)
	}
}

// A miss IS claimable — but only when the sensor proved it was watching by reporting something else
// in the same window. Otherwise the product could never say a control failed, which is the opposite
// error and just as useless.
func TestValidate_AMissIsClaimedOnlyWhenTheSensorWasDemonstrablyAwake(t *testing.T) {
	other := event("e-other", t0.Add(time.Minute), func(e *platform.RuntimeEvent) {
		e.AttackKind = "xss"
		e.Endpoint = "https://app/other"
	})
	r := dv.Validate([]dv.Probe{probe("c1")}, []platform.RuntimeEvent{other}, 0)
	if r.Results[0].Verdict != dv.NotDetected {
		t.Fatalf("the sensor was talking in this window, so this is a real miss: got %s", r.Results[0].Verdict)
	}
	if r.NotDetected != 1 {
		t.Errorf("want one miss, got %d", r.NotDetected)
	}
}

// The two strengths are never merged. A sensor reporting OUR token is exact; one reporting the same
// class against the same endpoint is an inference — right most of the time and wrong exactly when a
// real attacker is hitting that endpoint concurrently, which is when it matters most.
func TestValidate_MarkerAndCorrelatedAreDistinctEvidence(t *testing.T) {
	exact := dv.Validate([]dv.Probe{probe("c1")},
		[]platform.RuntimeEvent{event("e1", t0.Add(time.Hour*99), func(e *platform.RuntimeEvent) { e.Marker = "c1" })}, 0)
	if exact.Results[0].Strength != dv.StrengthMarker {
		t.Fatalf("a sensor reporting our own token is exact, got %s", exact.Results[0].Strength)
	}
	if exact.Results[0].Verdict != dv.Detected {
		t.Error("a marker match must be a detection even outside the timing window")
	}

	inferred := dv.Validate([]dv.Probe{probe("c1")},
		[]platform.RuntimeEvent{event("e2", t0.Add(time.Minute), nil)}, 0)
	if inferred.Results[0].Strength != dv.StrengthCorrelated {
		t.Fatalf("endpoint+class+timing is an inference, got %s", inferred.Results[0].Strength)
	}
	if !strings.Contains(inferred.Results[0].Why, "inference") {
		t.Errorf("an inferred match must say so, got: %s", inferred.Results[0].Why)
	}
}

// "We saw it" and "we stopped it" are materially different answers about a control.
func TestValidate_BlockedIsDistinctFromMerelyObserved(t *testing.T) {
	blocked := dv.Validate([]dv.Probe{probe("c1")},
		[]platform.RuntimeEvent{event("e1", t0.Add(time.Minute), func(e *platform.RuntimeEvent) { e.Blocked = true })}, 0)
	if !blocked.Results[0].Blocked || blocked.Blocked != 1 {
		t.Fatalf("an intervening control must be reported as such, got %+v", blocked.Results[0])
	}
	observed := dv.Validate([]dv.Probe{probe("c1")},
		[]platform.RuntimeEvent{event("e2", t0.Add(time.Minute), nil)}, 0)
	if observed.Results[0].Blocked || observed.Blocked != 0 {
		t.Error("a monitor-only sensor must not read as having stopped the attack")
	}
}

// An event outside the window is not evidence about this probe.
func TestValidate_TimingWindowIsRespected(t *testing.T) {
	late := event("e1", t0.Add(2*time.Hour), nil)
	r := dv.Validate([]dv.Probe{probe("c1")}, []platform.RuntimeEvent{late}, 10*time.Minute)
	if r.Results[0].Verdict == dv.Detected {
		t.Fatal("an event two hours later must not be attributed to this probe")
	}
	// ...and with nothing in the window, it is undetermined rather than a miss.
	if r.Results[0].Verdict != dv.Undetermined {
		t.Errorf("want undetermined, got %s", r.Results[0].Verdict)
	}
}

// A probe the RoE DENIED never left the building, so a control cannot be faulted for not seeing it.
// A probe with no canary cannot be joined at all and is never guessed at.
func TestProbesFrom_OnlyAttemptsThatActuallyFired(t *testing.T) {
	got := dv.ProbesFrom([]pentest.AttemptRecord{
		{Target: "a", Method: "exploit", Canary: "c1", Allowed: true, At: t0},
		{Target: "b", Method: "exploit", Canary: "c2", Allowed: false, At: t0}, // RoE denied it
		{Target: "c", Method: "exploit", Allowed: true, At: t0},                // no canary to join on
	})
	if len(got) != 1 || got[0].Canary != "c1" {
		t.Fatalf("only the allowed, canary-carrying attempt is a probe, got %+v", got)
	}
}

// "Your controls missed a probe" and "your controls missed the attack that WORKED" are the same
// sentence without this, and only the second is an incident. Proven rode on the Probe and was never
// read — the sharpest statement this package can make, flattened.
func TestValidate_AMissedProbeThatProvedSomethingIsCountedSeparately(t *testing.T) {
	awake := event("e-other", t0.Add(time.Minute), func(e *platform.RuntimeEvent) {
		e.AttackKind = "xss"
		e.Endpoint = "https://app/elsewhere"
	})
	harmless := probe("c1")
	worked := probe("c2")
	worked.Proven = true

	r := dv.Validate([]dv.Probe{harmless, worked}, []platform.RuntimeEvent{awake}, 0)
	if r.NotDetected != 2 {
		t.Fatalf("both probes were missed, got %d", r.NotDetected)
	}
	if r.MissedProven != 1 {
		t.Fatalf("only the one that PROVED a vulnerability counts here, got %d", r.MissedProven)
	}
	for _, res := range r.Results {
		if res.Canary == "c2" && !res.Proven {
			t.Error("the result must carry whether the probe proved something")
		}
		if res.Canary == "c1" && res.Proven {
			t.Error("a probe that proved nothing must not be marked proven")
		}
	}
}

// A DETECTED probe that proved something is not a miss, however much it worked.
func TestValidate_ProvenDoesNotInflateTheMissCount(t *testing.T) {
	worked := probe("c1")
	worked.Proven = true
	r := dv.Validate([]dv.Probe{worked},
		[]platform.RuntimeEvent{event("e1", t0.Add(time.Minute), nil)}, 0)
	if r.Detected != 1 || r.MissedProven != 0 {
		t.Fatalf("a detected proven probe is not a missed one, got %+v", r)
	}
}
