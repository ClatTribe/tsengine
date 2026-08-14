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
