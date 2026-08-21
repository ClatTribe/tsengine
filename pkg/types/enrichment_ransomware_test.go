package types

import (
	"strings"
	"testing"
	"time"
)

func TestL15Summary_RansomwareRidesAlongsideKEVNotInsteadOfIt(t *testing.T) {
	f := Finding{ThreatIntel: &ThreatIntel{KEV: &KEVStatus{
		Listed: true, Ransomware: true,
		DueDate: time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC),
	}}}
	s := f.L15Summary()
	if !strings.Contains(s, "KEV") || !strings.Contains(s, "RANSOMWARE") {
		t.Fatalf("an agent must see BOTH facts — exploited in the wild, and by ransomware crews: %q", s)
	}
	if !strings.Contains(s, "cisa-due:2026-01-31") {
		t.Fatalf("the authority's own deadline belongs in the digest: %q", s)
	}
}

func TestL15Summary_PlainKEVDoesNotClaimRansomware(t *testing.T) {
	f := Finding{ThreatIntel: &ThreatIntel{KEV: &KEVStatus{Listed: true}}}
	s := f.L15Summary()
	if strings.Contains(s, "RANSOMWARE") {
		t.Fatalf("most of the KEV catalog is not ransomware-linked; claiming it would train an agent to discount the label: %q", s)
	}
	if strings.Contains(s, "cisa-due") {
		t.Fatalf("no published deadline means none is shown: %q", s)
	}
}

// A finding that is not KEV-listed at all must show neither signal, even if the struct
// somehow carries them — Listed is the gate.
func TestL15Summary_UnlistedCVEShowsNoExploitationSignal(t *testing.T) {
	f := Finding{ThreatIntel: &ThreatIntel{KEV: &KEVStatus{Listed: false, Ransomware: true}}}
	if s := f.L15Summary(); strings.Contains(s, "RANSOMWARE") || strings.Contains(s, "KEV") {
		t.Fatalf("an unlisted CVE has no KEV claim to make: %q", s)
	}
}
