package platformapi

import (
	"strings"
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

// stampDetection records the DETECTION corpus's identity on a report — the twin of stampIntel, and
// for the same reason: a claim about what was found needs the state of what could find it.
//
// It reports what is knowable and refuses to invent the rest. A tag is not a build, so when that is
// all we have, RenderDetectionProvenance says the report cannot state which signatures ran. That
// sentence is the finding, not a gap in the finding.
func stampDetection(r *grc.VAPTReport, image string, _ time.Time) {
	if r == nil || strings.TrimSpace(image) == "" {
		return
	}
	r.Detection = &grc.DetectionProvenance{ImageRef: strings.TrimSpace(image)}
}
