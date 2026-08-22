package platformapi

import (
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
)

// stampIntel records, on a VAPT report, the state of the threat-intel corpus its exploitation
// claims were evaluated against.
//
// It lives here rather than in grc because reading it means touching the environment and the
// on-disk manifest, and grc's report builders are pure by design (the same reason Untested is
// filled by the caller). Both report handlers call it; a report that skipped it would state
// "N actively exploited (CISA KEV)" with nothing saying how old that answer is.
func stampIntel(r *grc.VAPTReport, now time.Time) {
	if r == nil {
		return
	}
	version, kevAsOf, epssAsOf := hooks.ThreatIntelCorpusInfo()
	age, stale, embedded := hooks.ThreatIntelAge(now)
	r.Intel = &grc.IntelProvenance{
		Version: version, KEVAsOf: kevAsOf, EPSSAsOf: epssAsOf,
		AgeDays: int(age.Hours() / 24), Stale: stale, Embedded: embedded,
	}
}
