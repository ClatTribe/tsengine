package threatintel

import (
	"strings"
	"testing"
	"time"
)

const kevJSON = `{
  "catalogVersion":"2026.08.21","dateReleased":"2026-08-21T08:00:00.000Z",
  "vulnerabilities":[
    {"cveID":"CVE-2026-1111","vendorProject":"Acme","product":"Gateway",
     "dateAdded":"2026-01-10","dueDate":"2026-01-31","knownRansomwareCampaignUse":"Known"},
    {"cveID":"CVE-2026-2222","vendorProject":"Acme","product":"Gateway",
     "dateAdded":"2026-02-10","dueDate":"2026-03-03","knownRansomwareCampaignUse":"Unknown"},
    {"cveID":"CVE-2026-3333","vendorProject":"Beta","product":"Server","dateAdded":"2026-03-10"}
  ]}`

func TestParseKEV_RansomwareAndDueDateAreNoLongerDiscarded(t *testing.T) {
	m, _, _, err := ParseKEV(strings.NewReader(kevJSON))
	if err != nil {
		t.Fatal(err)
	}
	r := m["CVE-2026-1111"]
	if !r.Ransomware {
		t.Fatal(`knownRansomwareCampaignUse "Known" must set Ransomware — it is the strongest free signal published`)
	}
	want := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	if !r.DueDate.Equal(want) {
		t.Fatalf("CISA's own due date must be carried, got %v want %v", r.DueDate, want)
	}
}

// "Unknown" is what CISA writes for MOST of the catalog. Treating any non-empty value
// as a yes would mark the majority as ransomware-linked — the alarm that teaches a team
// to ignore alarms.
func TestParseKEV_OnlyLiteralKnownCountsAsRansomware(t *testing.T) {
	m, _, _, _ := ParseKEV(strings.NewReader(kevJSON))
	if m["CVE-2026-2222"].Ransomware {
		t.Fatal(`"Unknown" must not read as known`)
	}
	if m["CVE-2026-3333"].Ransomware {
		t.Fatal("an absent field must not read as known")
	}
	// Both are still KEV-listed: the two facts are separate and must stay separate.
	if !m["CVE-2026-2222"].Listed || !m["CVE-2026-3333"].Listed {
		t.Fatal("every catalogued CVE is exploited in the wild regardless of ransomware use")
	}
}

func TestParseKEV_MissingDueDateIsZeroNotGuessed(t *testing.T) {
	m, _, _, _ := ParseKEV(strings.NewReader(kevJSON))
	if !m["CVE-2026-3333"].DueDate.IsZero() {
		t.Fatal("no published deadline means no deadline — deriving one would invent an authority's answer")
	}
}
