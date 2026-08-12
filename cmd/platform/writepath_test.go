package main

import (
	"os"
	"strings"
	"testing"
)

// §18.2 INVARIANT 3, PINNED: the only path to a customer's system is connector.Apply, and it is only
// ever reached after the HITL gate.
//
// remediate.Deliverer is the thing that actually writes to a customer's world — opening a PR, changing
// a cloud setting, suspending an account. Today it is constructed once and handed to exactly one
// owner, hitl.Desk, so every write passes the tier rules, the kill-switch and the signed ledger. That
// is not enforced anywhere; it is true because of how one file happens to be wired.
//
// The failure it guards against is quiet and plausible: someone needs "just this one" automated fix and
// passes the deliverer to the runner, or a handler, or a scheduler. Nothing would break. Tests would
// pass. The product would simply start changing customer systems without asking, and the first person
// to find out would be a customer.
//
// A source-level guard is the honest instrument here for the same reason as the scheduled-pentest one:
// the behavioural difference only shows up against a real customer system, which no test has.
// mentionsAsValue reports whether the identifier appears as a VALUE rather than as the receiver of a
// field access — `Apply: deliverer` counts, `deliverer.Ticket = x` does not.
func mentionsAsValue(line, name string) bool {
	for i := 0; i+len(name) <= len(line); i++ {
		if line[i:i+len(name)] != name {
			continue
		}
		// preceded by an identifier character → part of a longer name
		if i > 0 && isIdentByte(line[i-1]) {
			continue
		}
		rest := line[i+len(name):]
		if strings.HasPrefix(rest, ".") { // field access on the deliverer itself
			continue
		}
		if strings.HasPrefix(rest, " :=") || strings.HasPrefix(rest, ":=") { // its own declaration
			continue
		}
		return true
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func TestWritePath_DelivererGoesOnlyToTheHITLDesk(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(src), "\n")

	// The variable the Deliverer is bound to, whatever it is called.
	name := ""
	for _, l := range lines {
		if i := strings.Index(l, "remediate.Deliverer{"); i >= 0 {
			if eq := strings.Index(l, ":="); eq > 0 {
				name = strings.TrimSpace(l[:eq])
			}
			break
		}
	}
	if name == "" {
		t.Skip("no remediate.Deliverer constructed in main.go — if the wiring moved, re-point this guard " +
			"rather than deleting it")
	}

	var holders []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "//") || !strings.Contains(l, name) {
			continue
		}
		if strings.Contains(l, "remediate.Deliverer{") {
			continue // the construction itself
		}
		// `deliverer.Field = ...` configures its OWN state (which tracker it files to, etc). That is not
		// handing the write capability to anyone, so it is not what this guards. What matters is the
		// deliverer passed AS A VALUE to something else — that is a new holder of the ability to write
		// to a customer's system.
		if !mentionsAsValue(l, name) {
			continue
		}
		holders = append(holders, trimmed)
	}

	for _, h := range holders {
		if strings.Contains(h, "hitl.Desk{") || strings.Contains(h, "Apply:") {
			continue // the sanctioned owner: the gate
		}
		t.Errorf("GATE BYPASSED: the remediation deliverer (%q) is handed to something other than "+
			"hitl.Desk:\n    %s\nEvery write to a customer's system must pass the desk — the tier rules, "+
			"the kill-switch and the signed ledger all live there (§18.2 inv. 3). If this is deliberate, "+
			"the invariant is changing and that is a decision to make explicitly.", name, h)
	}
}
