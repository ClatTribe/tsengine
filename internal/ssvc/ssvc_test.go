package ssvc

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestDecide_ActiveHighImpact_Act(t *testing.T) {
	added := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := Decide(Input{KEVListed: true, KEVDateAdded: added, CVSS: 9.8, HighSeverity: true})
	if got == nil || got.Decision != "act" {
		t.Fatalf("KEV + high impact must be ACT, got %+v", got)
	}
	if got.Exploitation != "active" {
		t.Errorf("KEV → active exploitation, got %s", got.Exploitation)
	}
	if got.DueDate != "2026-01-22" { // added + 21d
		t.Errorf("KEV must carry a BOD 22-01 due date, got %q", got.DueDate)
	}
}

func TestDecide_ActiveLowImpact_Attend(t *testing.T) {
	got := Decide(Input{KEVListed: true, CVSS: 4.0, HighSeverity: false})
	if got == nil || got.Decision != "attend" {
		t.Fatalf("KEV + low impact must be ATTEND, got %+v", got)
	}
}

func TestDecide_PocHighImpact_Attend(t *testing.T) {
	got := Decide(Input{ExploitExists: true, CVSS: 8.1, HighSeverity: true})
	if got == nil || got.Decision != "attend" || got.Exploitation != "poc" {
		t.Fatalf("public exploit + high impact must be ATTEND/poc, got %+v", got)
	}
	if !got.Automatable {
		t.Error("a ready-made exploit is automatable")
	}
	if got.DueDate != "" {
		t.Error("non-KEV must carry no BOD due date")
	}
}

func TestDecide_NoneLowImpact_Track(t *testing.T) {
	got := Decide(Input{CVSS: 3.1, HighSeverity: false, EPSS: 0.01})
	if got == nil || got.Decision != "track" || got.Exploitation != "none" {
		t.Fatalf("no exploitation + low impact must be TRACK/none, got %+v", got)
	}
}

func TestDecide_HighEPSS_IsPoc(t *testing.T) {
	got := Decide(Input{EPSS: 0.8, CVSS: 7.5, HighSeverity: true})
	if got == nil || got.Exploitation != "poc" {
		t.Errorf("high EPSS should read as poc-level exploitation, got %+v", got)
	}
}

func TestDecide_NoSignal_Nil(t *testing.T) {
	if got := Decide(Input{}); got != nil {
		t.Errorf("no signal → nil decision (§10), got %+v", got)
	}
}

// TestAutomatable_FromVector: AV:N + AC:L is automatable even without a packaged exploit.
func TestDecide_Automatable_FromVector(t *testing.T) {
	got := Decide(Input{CVSS: 7.5, HighSeverity: true, CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"})
	if got == nil || !got.Automatable {
		t.Errorf("AV:N + AC:L must be automatable, got %+v", got)
	}
}

func TestFromThreatIntel(t *testing.T) {
	ti := &types.ThreatIntel{
		CVSS:     9.1,
		KEV:      &types.KEVStatus{Listed: true, DateAdded: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		Exploits: []string{"metasploit:exploit/x"},
	}
	got := FromThreatIntel(ti, true)
	if got == nil || got.Decision != "act" {
		t.Fatalf("KEV + weaponized + high → ACT, got %+v", got)
	}
	if FromThreatIntel(nil, true) != nil {
		t.Error("nil ThreatIntel → nil")
	}
}
