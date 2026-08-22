package hooks

import (
	"os"
	"time"

	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
)

// ThreatIntelMaxAge is how old the intel may be before the claims built on it stop holding.
//
// Thirty days, from what the feeds do rather than from taste: CISA adds to KEV most weeks, EPSS
// re-scores daily, and BOD 22-01 remediation windows are counted in weeks — so a month-old corpus
// has missed several rounds of "this is now being exploited" and is scoring patch priority against
// probabilities that have moved.
const ThreatIntelMaxAge = 30 * 24 * time.Hour

// ThreatIntelAge reports how old the pinned intel is, whether that age undermines what is built on
// it, and whether this deployment is running on the EMBEDDED snapshot rather than a refreshed corpus.
//
// WHY THIS EXISTS. The corpus records KEVAsOf and EPSSAsOf and nothing ever asked. Refresh is
// best-effort by design — "a failed fetch keeps the last good corpus, never blocks scans" — which is
// the right call for availability and means a refresh that has been failing for weeks is
// indistinguishable from one that ran this morning.
//
// The default is worse than the failure case. With TSENGINE_THREAT_INTEL_CORPUS unset the engine
// uses a snapshot compiled into the binary, frozen at whatever date it was built. Every CVE added to
// KEV since then is unflagged: no KEV badge, no ransomware flag, no BOD 22-01 SLA acceleration, no
// CISA due date — and a finding for something that became actively exploited last month reads as an
// ordinary medium.
//
// None of that is a wrong answer we could catch. It is the RIGHT answer to a question asked of
// last quarter's world, which is why the age has to be visible rather than inferred from a version
// string nobody reads.
func ThreatIntelAge(now time.Time) (age time.Duration, stale, embedded bool) {
	_, kevAsOf, epssAsOf := ThreatIntelCorpusInfo()
	embedded = os.Getenv(ThreatIntelCorpusEnv) == ""
	if embedded {
		// A configured path that fails to load also lands here (ThreatIntelCorpusInfo falls back),
		// and that is correct: the engine really is serving embedded data either way.
		embedded = true
	} else if _, err := threatintel.LoadManifest(os.Getenv(ThreatIntelCorpusEnv)); err != nil {
		embedded = true
	}

	// The OLDER of the two, because a finding's priority leans on both and the weaker one bounds the
	// claim. Taking the newer would let a daily EPSS refresh hide a KEV feed that stopped months ago.
	asOf := kevAsOf
	if epssAsOf.Before(asOf) {
		asOf = epssAsOf
	}
	if asOf.IsZero() {
		// No date at all: not evidence of freshness. Reported stale with a zero age rather than
		// treated as current, since "we do not know when this is from" cannot support a KEV claim.
		return 0, true, embedded
	}
	age = now.Sub(asOf)
	if age < 0 {
		age = 0 // a corpus stamped in the future is a clock problem, not freshness to celebrate
	}
	return age, age > ThreatIntelMaxAge, embedded
}
