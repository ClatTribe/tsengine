package grc

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestSeedAttestations_DeterministicAndPending(t *testing.T) {
	got := SeedAttestations("soc2", []string{"CC6.6", "CC6.1", "CC6.1", "", "CC7.1"})
	if len(got) != 3 { // dedup + drop empty
		t.Fatalf("want 3 unique controls, got %d: %+v", len(got), got)
	}
	// sorted by control id
	if got[0].ControlID != "CC6.1" || got[1].ControlID != "CC6.6" || got[2].ControlID != "CC7.1" {
		t.Fatalf("controls not sorted: %+v", got)
	}
	for _, c := range got {
		if c.Verdict != platform.AttestPending || c.Framework != "soc2" {
			t.Errorf("each seeded control must be pending+framework-tagged, got %+v", c)
		}
	}
}

func TestSummarizeAudit(t *testing.T) {
	e := platform.AuditEngagement{Attestations: []platform.ControlAttestation{
		{ControlID: "a", Verdict: platform.AttestPassed},
		{ControlID: "b", Verdict: platform.AttestPassed},
		{ControlID: "c", Verdict: platform.AttestException},
		{ControlID: "d", Verdict: platform.AttestPending},
	}}
	s := SummarizeAudit(e)
	if s.Total != 4 || s.Passed != 2 || s.Exceptions != 1 || s.Pending != 1 || s.Attested != 3 {
		t.Fatalf("tallies wrong: %+v", s)
	}
	if s.Percent != 75 { // 3/4 attested
		t.Errorf("percent = %d, want 75", s.Percent)
	}
	if s.Ready { // has an exception + a pending → not ready
		t.Error("engagement with an exception/pending must NOT be ready")
	}

	// all passed → ready
	allPass := platform.AuditEngagement{Attestations: []platform.ControlAttestation{
		{ControlID: "a", Verdict: platform.AttestPassed},
		{ControlID: "b", Verdict: platform.AttestPassed},
	}}
	if !SummarizeAudit(allPass).Ready {
		t.Error("all-passed engagement must be ready")
	}
}

func TestAuditProgress(t *testing.T) {
	e := platform.AuditEngagement{Attestations: []platform.ControlAttestation{
		{Verdict: platform.AttestPassed}, {Verdict: platform.AttestPending},
	}}
	a, total := e.Progress()
	if a != 1 || total != 2 {
		t.Errorf("progress = %d/%d, want 1/2", a, total)
	}
}
