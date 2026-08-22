package hooks

import (
	"testing"
	"time"
)

// The default deployment serves intel frozen at build time, and nothing said so.
//
// Measured when this was written: 113 days old, on a default build, with TSENGINE_THREAT_INTEL_CORPUS
// unset — which is the documented default. Every CVE added to CISA KEV in those months is unflagged,
// so there is no known-exploited badge, no ransomware flag and no accelerated BOD 22-01 deadline, and
// a finding for something that became actively exploited in June reads as an ordinary medium.
func TestThreatIntelAge_EmbeddedSnapshotIsReportedStaleOnceItAges(t *testing.T) {
	age, stale, embedded := ThreatIntelAge(ThreatIntelSnapshot.Add(120 * 24 * time.Hour))
	if !stale {
		t.Error("a four-month-old corpus must be reported stale — the priorities built on it are " +
			"correct for a world that has moved on")
	}
	if !embedded {
		t.Error("with no corpus path configured this IS the embedded snapshot, and the customer " +
			"needs to be told which one they are on to know what to do about it")
	}
	if d := int(age.Hours() / 24); d != 120 {
		t.Errorf("age = %d days, want 120", d)
	}
}

// Fresh intel says nothing. A bar that warns constantly is one people stop reading.
func TestThreatIntelAge_FreshCorpusIsNotFlagged(t *testing.T) {
	if _, stale, _ := ThreatIntelAge(ThreatIntelSnapshot.Add(2 * 24 * time.Hour)); stale {
		t.Error("two days old is current")
	}
}

// The boundary, both sides, so the threshold means what the constant says.
func TestThreatIntelAge_ThresholdBoundary(t *testing.T) {
	if _, stale, _ := ThreatIntelAge(ThreatIntelSnapshot.Add(ThreatIntelMaxAge)); stale {
		t.Error("exactly at the limit is not yet over it")
	}
	if _, stale, _ := ThreatIntelAge(ThreatIntelSnapshot.Add(ThreatIntelMaxAge + time.Hour)); !stale {
		t.Error("past the limit is stale")
	}
}

// A corpus stamped in the future is a clock problem. It must not read as freshness, and it must not
// produce a negative age that renders as "-3 days old".
func TestThreatIntelAge_FutureStampIsNotFreshness(t *testing.T) {
	age, stale, _ := ThreatIntelAge(ThreatIntelSnapshot.Add(-100 * 24 * time.Hour))
	if age < 0 {
		t.Errorf("negative age %v would render as a nonsense sentence", age)
	}
	if stale {
		t.Error("a future stamp is not evidence of staleness either — it is a clock to fix, and " +
			"claiming staleness we cannot support is the same overclaim pointed the other way")
	}
}
