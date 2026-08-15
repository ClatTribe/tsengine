package platformapi

import (
	"fmt"
	"strings"
)

// unjudged.go: saying so when we could not assess what was posted.
//
// Every snapshot assessor skips an item it cannot identify — a device with no name, a vendor with no
// name — because a finding that cannot name what it is about is unactionable (§10). That skip is
// correct. Reporting it as nothing is not.
//
// The failure looks like this. An MDM export whose device-name field is spelled differently drops every
// device, and the response says {"devices": 2, "issues_detected": 0}. Read that as a human: we checked
// two laptops and your fleet is clean. What actually happened is that we read nothing at all. For disk
// encryption that number is a compliance claim, so a silent skip does not merely lose a finding — it
// manufactures assurance the evidence never supported.
//
// This is the same discipline the assessors already apply to absent CONFIG (absent is not "off"),
// carried up to the transport: absent DATA is not "clean".

// unjudgedNote returns a one-line honest note when some of what was posted could not be assessed, and
// an empty string when everything was. The caller attaches it to the response as `checks_not_run`.
//
// names carries the identifiers we could not use — usually empty strings, which is precisely the
// problem — so the count is what is reportable, not the labels.
func unjudgedNote(posted, judged int, singular, plural, why string) string {
	skipped := posted - judged
	if skipped <= 0 {
		return ""
	}
	noun := plural
	verb := "were"
	if skipped == 1 {
		noun, verb = singular, "was"
	}
	return fmt.Sprintf("%d of %d %s %s not assessed because %s. An export we could not read is not a "+
		"clean result — check the field names in your export and post it again.", skipped, posted, noun, verb, why)
}

// countNamed reports how many of the posted items carry a usable identifier, which is the same test
// each assessor applies before it will say anything about an item. It lives here, next to the note, so
// the two cannot drift into disagreeing about what "assessed" means.
func countNamed(names []string) int {
	n := 0
	for _, s := range names {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}

// noInputNote returns an honest note when the post contained NOTHING to assess, and an empty string
// otherwise.
//
// This is a different fact from unjudgedNote's, which is why it is a different sentence. That one
// says "you sent 12 and we could read 9"; this one says "you sent none". Overloading one function
// with both would make the empty case read as a skip, and a reader would go looking for the items
// that were dropped.
//
// The gap it closes: posting an empty list returned {"devices": 0, "issues_detected": 0} with no
// comment. Every assessor correctly found nothing — there was nothing to find — but the response is
// indistinguishable from a fleet that was examined and came back clean, and disk encryption is a
// claim that ends up in front of an auditor. A collector that ran and returned nothing looks exactly
// like this, which is the case worth catching.
func noInputNote(posted int, plural string) string {
	if posted > 0 {
		return ""
	}
	return "No " + plural + " were in this submission, so none were assessed. This is not a clean " +
		"result — if you expected data here, check that the collector or export actually produced it."
}

// ingestNotes composes the two honest notes an ingest can owe its caller: nothing was sent, or some
// of what was sent could not be read. Returns nil when the whole batch was assessed, so a response
// carries no note when it has nothing to disclose.
//
// Kept next to both notes so an ingest cannot pick up one check and miss the other — which is how
// the empty case survived: every ingest adopted unjudgedNote and none of them covered zero.
func ingestNotes(posted, judged int, singular, plural, why string) []string {
	var out []string
	if n := noInputNote(posted, plural); n != "" {
		out = append(out, n)
	}
	if n := unjudgedNote(posted, judged, singular, plural, why); n != "" {
		out = append(out, n)
	}
	return out
}
