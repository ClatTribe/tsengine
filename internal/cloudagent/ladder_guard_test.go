package cloudagent

import (
	"strings"
	"testing"
)

// The verification ladder (exploitprobe.go header) is only as strong as the text the MODEL reads.
// A policy-simulator ALLOW confirms AUTHORIZATION for one (principal, action, resource, context)
// tuple at one moment; it does not prove exploitability, which additionally needs network
// reachability, credential acquisition, unsupplied session context and the rest of the workflow.
//
// This guard exists because that overclaim already shipped once and survived a fix: ADR 0024's C1
// correction was applied to check_reachable's result text but NOT to the resolve_access CATALOG
// description, which still read "ALLOW=confirmed exploitable" — in the more frequently called of the
// two tools, in the exact sentence the model consults when deciding what to record. Fixing the
// instance and not the class is what let it survive, so this checks EVERY tool description.
func TestToolDescriptions_NeverEquateAnAllowWithExploitability(t *testing.T) {
	// Phrases that assert exploitability from an authorization answer. Lowercased before matching.
	forbidden := []string{
		"confirmed exploitable",
		"proven exploitable",
		"proves exploitab",
		"= exploitable",
		"is exploitable",
	}
	defs := tools()
	// §14.2 rule 6: a guard that cannot see its subject must FAIL, not pass vacuously. An empty
	// catalog, or one where no description discusses the dry-run at all, means this guard has
	// stopped guarding — which is exactly when the overclaim would return unnoticed.
	if len(defs) == 0 {
		t.Fatal("tool catalog is empty: this guard cannot see its subject")
	}
	sawDryRun := false
	for _, d := range defs {
		low := strings.ToLower(d.help)
		if strings.Contains(low, "allow") && strings.Contains(low, "dry-run") {
			sawDryRun = true
		}
		for _, bad := range forbidden {
			if strings.Contains(low, bad) {
				t.Errorf("tool %q description claims exploitability from an authorization answer (%q).\n"+
					"A provider ALLOW is provider-confirmed AUTHORIZATION for ONE action, not proof the "+
					"move is exploitable (ADR 0024 C1). Say which rung it is.", d.name, bad)
			}
		}
	}
	if !sawDryRun {
		t.Fatal("no tool description mentions the provider dry-run + ALLOW any more: " +
			"this guard is no longer reading the text it was written to police")
	}
}
