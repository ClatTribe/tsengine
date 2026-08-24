package grc

import (
	"fmt"
	"strings"
	"time"
)

// Provenance for the VAPT report: WHEN each finding was observed, and HOW OLD the threat
// intelligence behind its priority claims is.
//
// The second is the load-bearing one. This report states "N actively exploited (CISA KEV)" and
// "N ransomware-linked", and on a default build those claims are evaluated against a KEV/EPSS
// snapshot COMPILED INTO THE BINARY and frozen at its build date (see hooks.ThreatIntelAge, which
// measured 113 days on a default build). Every CVE that became actively exploited since then is
// unflagged — so "0 actively exploited" can mean "nothing is being exploited" or "we last looked
// four months ago", and the report renders both identically.
//
// That is the same false-all-clear shape as an unscanned scope reading "clean", arriving through
// the intel rather than the scan. A report a customer forwards to an auditor has to say which one
// it is, and it has to say it where the claim is made.
//
// grc stays PURE: this file defines the shape and the wording, and the caller (which can read the
// environment and the on-disk manifest) fills it in — the same split as Untested/Reassess.

// IntelProvenance is the pinned state of the threat-intel corpus the report's KEV/EPSS/ransomware
// claims were evaluated against.
type IntelProvenance struct {
	Version  string    `json:"version,omitempty"`  // the pinned corpus version
	KEVAsOf  time.Time `json:"kev_as_of,omitzero"` // CISA KEV snapshot date
	EPSSAsOf time.Time `json:"epss_as_of,omitzero"`
	AgeDays  int       `json:"age_days"`
	// Stale: older than the window in which the feeds meaningfully change (CISA adds to KEV most
	// weeks). Embedded: running the snapshot compiled into the binary rather than a refreshed corpus.
	Stale    bool `json:"stale"`
	Embedded bool `json:"embedded"`
}

// IntelCaveat is the sentence the report must carry when the intel behind its exploitation claims
// is too old to support them, or "" when the corpus is current. It names the age and says which
// specific claims are affected — a generic "data may be out of date" tells a reader nothing about
// whether to trust the number they are looking at.
func (p *IntelProvenance) IntelCaveat() string {
	if p == nil || (!p.Stale && !p.Embedded) {
		return ""
	}
	var b strings.Builder
	b.WriteString("**The exploitation intelligence behind this report is not current.** ")
	switch {
	case p.Embedded && p.AgeDays > 0:
		fmt.Fprintf(&b, "This assessment used the threat-intel snapshot built into the engine, %s old. ", days(p.AgeDays))
	case p.Embedded:
		b.WriteString("This assessment used the threat-intel snapshot built into the engine rather than a refreshed feed. ")
	default:
		fmt.Fprintf(&b, "The threat-intel corpus is %s old. ", days(p.AgeDays))
	}
	b.WriteString("The “actively exploited (CISA KEV)”, “ransomware-linked” and exploit-probability " +
		"figures therefore reflect what was known as of that date, not today. A vulnerability that " +
		"began being exploited since then appears here as an ordinary finding — so a low count of " +
		"actively-exploited issues is not evidence that none exist. Refresh the corpus and re-generate " +
		"this report before relying on those figures.")
	return b.String()
}

func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// RenderIntelProvenance is the provenance line for the methodology section: what the exploitation
// claims were evaluated against, so an auditor can see the state rather than infer it.
func RenderIntelProvenance(p *IntelProvenance) string {
	if p == nil {
		return ""
	}
	var parts []string
	if p.Version != "" {
		parts = append(parts, "corpus `"+p.Version+"`")
	}
	if !p.KEVAsOf.IsZero() {
		parts = append(parts, "CISA KEV as of "+p.KEVAsOf.UTC().Format("2006-01-02"))
	}
	if !p.EPSSAsOf.IsZero() {
		parts = append(parts, "EPSS as of "+p.EPSSAsOf.UTC().Format("2006-01-02"))
	}
	if p.Embedded {
		parts = append(parts, "engine-embedded snapshot")
	}
	if len(parts) == 0 {
		return ""
	}
	return "**Threat intelligence:** " + strings.Join(parts, " · ") + "."
}

// cvssVectorProse decodes a CVSS v3.x base vector into the sentence a reader can act on. It is a
// pure expansion of the vector's own metrics as the standard defines them — no inference, no
// severity judgement of our own layered on top.
//
// It exists because the vector is the half of the CVSS line that carries the ACTIONABLE detail —
// "reachable from the internet with no credentials and no user interaction" is a different
// remediation conversation from "needs local access and an admin" — and `AV:N/AC:L/PR:N/UI:N/…`
// says that only to a reader who has the metric table memorised. The raw vector is still printed
// alongside, because that is the form an auditor cross-checks.
//
// An unrecognised metric or value is SKIPPED, never guessed: a future CVSS revision adding a
// metric must produce a shorter sentence, not a confident wrong one. Returns "" if nothing in the
// vector was recognised.
func cvssVectorProse(vec string) string {
	metrics := map[string]map[string]string{
		"AV": {"N": "reachable over the network", "A": "reachable from an adjacent network",
			"L": "requires local access", "P": "requires physical access"},
		"AC": {"L": "low attack complexity", "H": "high attack complexity"},
		"PR": {"N": "no privileges needed", "L": "needs low privileges", "H": "needs high privileges"},
		"UI": {"N": "no user interaction", "R": "requires user interaction"},
		"S":  {"C": "can affect other components (scope change)", "U": ""}, // unchanged scope is the norm; saying so is noise
	}
	// Order is the standard's, so the sentence reads the same way every time.
	order := []string{"AV", "AC", "PR", "UI", "S"}
	found := map[string]string{}
	var impact []string
	for _, tok := range strings.Split(vec, "/") {
		k, v, ok := strings.Cut(strings.TrimSpace(tok), ":")
		if !ok {
			continue
		}
		k, v = strings.ToUpper(k), strings.ToUpper(v)
		switch k {
		case "C", "I", "A":
			if name := impactName(k, v); name != "" {
				impact = append(impact, name)
			}
			continue
		case "CVSS": // the version prefix, not a metric
			continue
		}
		if vals, known := metrics[k]; known {
			if phrase, knownVal := vals[v]; knownVal && phrase != "" {
				found[k] = phrase
			}
		}
	}
	var parts []string
	for _, k := range order {
		if p := found[k]; p != "" {
			parts = append(parts, p)
		}
	}
	if len(impact) > 0 {
		parts = append(parts, "high impact to "+joinAnd(impact))
	}
	if len(parts) == 0 {
		return ""
	}
	return capitalize(strings.Join(parts, ", ")) + "."
}

// impactName names a HIGH confidentiality/integrity/availability impact. Only High is reported:
// the point of the sentence is what an attacker fully gains, and listing "low impact to
// availability" alongside it flattens the distinction the metric exists to draw.
func impactName(metric, value string) string {
	if value != "H" {
		return ""
	}
	switch metric {
	case "C":
		return "confidentiality"
	case "I":
		return "integrity"
	case "A":
		return "availability"
	}
	return ""
}

func joinAnd(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	case 2:
		return s[0] + " and " + s[1]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// ── The DETECTION corpus — the other half, and the one that was missing ─────────────────────────
//
// An audit found the report scrupulous about the INTEL corpus's age and silent about the DETECTION
// corpus's. That asymmetry matters because they answer different questions and only one of them was
// being asked:
//
//	intel     → how confident are we about the PRIORITY of what we found (KEV, EPSS, ransomware)
//	detection → what were we CAPABLE OF FINDING AT ALL
//
// The second determines the finding count. nuclei's templates are baked into the sandbox image at
// build time and have no runtime refresh, so on a deployment running a months-old image the report's
// "0 findings" is partly a statement about our signatures rather than about the customer — and the
// document said nothing that would let a reader tell.
//
// The honest hard case is a TAG. If the deployment runs `tsengine/sandbox:latest`, the report cannot
// say what tested the customer, because the tag does not identify a build. Saying so is the point:
// an unanswerable question rendered as silence reads as a clean answer.

// DetectionProvenance is the state of the SIGNATURE corpora a scan's findings came from.
type DetectionProvenance struct {
	// ImageRef is the sandbox image as configured — possibly a mutable tag, which is why Digest exists.
	ImageRef string `json:"image_ref,omitempty"`
	// Digest is the immutable image identity, when a scan resolved one.
	Digest string `json:"digest,omitempty"`
	// BuiltAt is when that image was built, when known. The baked corpora are as old as this.
	BuiltAt time.Time `json:"built_at,omitzero"`
	AgeDays int       `json:"age_days,omitempty"`
	// Stale: the baked corpora are older than the window in which detection content meaningfully moves.
	Stale bool `json:"stale,omitempty"`
}

// DetectionStaleAfterDays is when baked signatures stop being a current answer. Deliberately shorter
// than the intel window: nuclei merges templates most days, so a month-old template set is a
// materially different scanner from a current one.
const DetectionStaleAfterDays = 30

// RenderDetectionProvenance states what was capable of finding things, for the methodology section.
//
// It returns a sentence even when almost nothing is known, because "we cannot tell you which
// signatures tested you" is the most important version of this line, not the one to omit.
func RenderDetectionProvenance(p *DetectionProvenance) string {
	if p == nil {
		return ""
	}
	var parts []string
	switch {
	case p.Digest != "":
		parts = append(parts, "sandbox image `"+shortDigest(p.Digest)+"`")
	case p.ImageRef != "":
		parts = append(parts, "sandbox image `"+p.ImageRef+"`")
	}
	if !p.BuiltAt.IsZero() {
		line := "built " + p.BuiltAt.UTC().Format("2006-01-02")
		if p.AgeDays > 0 {
			line += " (" + days(p.AgeDays) + " ago)"
		}
		parts = append(parts, line)
	}
	if len(parts) == 0 {
		return ""
	}
	s := "**Detection corpus:** " + strings.Join(parts, " · ") + ". " +
		"Baked signatures — the nuclei template set — move only when this image is rebuilt; " +
		"trivy, grype and semgrep fetch theirs at scan time."
	// A tag is not a build. Say so rather than letting the reference look like an identity.
	if p.Digest == "" && p.ImageRef != "" && p.BuiltAt.IsZero() {
		s += " The image is identified by a mutable tag and no build date was recorded, so this " +
			"report cannot state which signature versions tested this scope."
	}
	return s
}

// DetectionCaveat is the warning that belongs next to the finding count when the baked signatures
// are old enough that a low count is partly about us. Mirrors IntelCaveat deliberately — a reader
// who has learned to look for one should find the other in the same place, in the same shape.
func (p *DetectionProvenance) DetectionCaveat() string {
	if p == nil {
		return ""
	}
	if !p.Stale && p.AgeDays <= DetectionStaleAfterDays {
		return ""
	}
	var b strings.Builder
	b.WriteString("**The detection signatures behind this report are not current.** ")
	if p.AgeDays > 0 {
		fmt.Fprintf(&b, "The sandbox image carrying them was built %s ago. ", days(p.AgeDays))
	}
	b.WriteString("Its baked template set has no runtime refresh, so checks published since that " +
		"build did not run here. A finding count is therefore partly a statement about which " +
		"signatures were available, not only about this scope — rebuild the scanning image and " +
		"re-run before reading a low count as an all-clear.")
	return b.String()
}

// shortDigest trims sha256:<64> to something a report can print without wrapping, keeping enough to
// identify the build.
func shortDigest(d string) string {
	if i := strings.Index(d, ":"); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}
