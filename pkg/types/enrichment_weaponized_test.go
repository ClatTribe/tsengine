package types

import (
	"strings"
	"testing"
)

// weaponized rides ALONGSIDE pub-exploit, never instead of it. They are different claims —
// a PoC exists, versus somebody has already done the work of turning it into a tool — and
// collapsing them would lose the one that changes what gets patched first.
func TestL15Summary_WeaponizedIsItsOwnRung(t *testing.T) {
	poc := Finding{ThreatIntel: &ThreatIntel{Exploits: []string{"exploitdb:EDB-50592"}}}
	if got := poc.L15Summary(); !strings.Contains(got, "pub-exploit") || strings.Contains(got, "weaponized") {
		t.Errorf("a PoC alone = %q; want pub-exploit and NOT weaponized", got)
	}

	weap := Finding{ThreatIntel: &ThreatIntel{Exploits: []string{
		"exploitdb:EDB-50592", "metasploit:exploit/multi/http/log4shell",
	}}}
	got := weap.L15Summary()
	if !strings.Contains(got, "pub-exploit") {
		t.Errorf("%q lost pub-exploit — weaponized adds a rung, it does not replace one", got)
	}
	if !strings.Contains(got, "weaponized") {
		t.Errorf("%q is missing weaponized", got)
	}
}

// Weaponized is not KEV. A module existing says an operator can run it tonight; it says
// nothing about whether anyone has. Reporting one as the other would put a CVE nobody has
// touched on the CISA clock.
func TestL15Summary_WeaponizedIsNotKEV(t *testing.T) {
	f := Finding{ThreatIntel: &ThreatIntel{Exploits: []string{"metasploit:exploit/x"}}}
	if got := f.L15Summary(); strings.Contains(got, "KEV") {
		t.Errorf("%q claims KEV from a Metasploit module alone", got)
	}
}

// One weaponized ref is one tag, however many modules exist.
func TestL15Summary_WeaponizedTaggedOnce(t *testing.T) {
	f := Finding{ThreatIntel: &ThreatIntel{Exploits: []string{
		"metasploit:exploit/a", "metasploit:exploit/b", "metasploit:exploit/c",
	}}}
	if n := strings.Count(f.L15Summary(), "weaponized"); n != 1 {
		t.Errorf("weaponized appears %d times, want 1", n)
	}
}
