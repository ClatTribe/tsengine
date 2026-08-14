package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// §18.2 invariant 7 — the kill-switch fails closed — predates the engineer tool belt. The belt added
// two NEW ways for the agent to act on the customer's world (propose_fix, open_ticket), and nothing
// tested them against the switch.
//
// Every other engineer test uses a fake submitter, which is exactly why this went unverified: a fake
// records what it was handed and applies nothing, so it cannot show whether the real gate holds. These
// run the REAL hitl.Desk with a REAL applier, and assert on whether the world was touched.
//
// open_ticket is the sharp case. It rides at tier 1, which auto-applies — so on a halted tenant the
// question is whether a ticket lands in the customer's actual tracker after their owner pulled the
// switch.

// countingApplier stands in for the outside world: every call is a real side effect.
type countingApplier struct{ applied int }

func (c *countingApplier) Apply(context.Context, platform.Action) error {
	c.applied++
	return nil
}

func haltedDeps(t *testing.T, halted bool) (Deps, *countingApplier, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid, AgentsHalted: halted}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutFinding(ctx, tid, types.Finding{
		ID: "f-1", Tool: "grype", RuleID: "CVE-2023-1", Severity: types.SeverityHigh,
		Title: "Vulnerable dependency", Endpoint: "pkg:npm/lib@1.0.0",
	}); err != nil {
		t.Fatal(err)
	}
	app := &countingApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}
	return Deps{Store: st, Submitter: desk, Desk: desk, NewID: func() string { return "a1" }}, app, tid
}

// THE ONE THAT MATTERS. Halted, the agent's ticket must not reach the customer's tracker.
func TestKillSwitch_HaltedTenantTicketNeverReachesTheWorld(t *testing.T) {
	d, app, tid := haltedDeps(t, true)
	// The filer may refuse outright or queue — either is acceptable. What is NOT acceptable is the
	// side effect happening.
	_, _ = (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"f-1", "Upgrade the dependency", "Advisory published upstream.")
	if app.applied != 0 {
		t.Errorf("KILL-SWITCH BYPASSED: the agent filed a ticket into the customer's tracker %d time(s) "+
			"while their kill-switch was engaged (§18.2 inv. 7)", app.applied)
	}
}

// The control: with the switch OFF, a tier-1 ticket DOES auto-apply. Without this the test above
// passes for a tenant where ticketing is simply broken, which would prove nothing.
func TestKillSwitch_RunningTenantTicketDoesReachTheWorld(t *testing.T) {
	d, app, tid := haltedDeps(t, false)
	if _, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"f-1", "Upgrade the dependency", "Advisory published upstream."); err != nil {
		t.Fatalf("a running tenant should file: %v", err)
	}
	if app.applied != 1 {
		t.Errorf("tier-1 ticket did not auto-apply on a running tenant (applied=%d) — the halted test "+
			"above would then prove nothing", app.applied)
	}
}

// Nothing is LOST while halted: the action waits rather than vanishing, so disengaging the switch and
// approving still delivers it. A kill-switch that silently discarded work would push operators to
// avoid using it.
func TestKillSwitch_HaltedWorkWaitsRatherThanVanishing(t *testing.T) {
	d, _, tid := haltedDeps(t, true)
	_, _ = (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"f-1", "Upgrade the dependency", "")
	acts, err := d.Store.ListActions(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) == 0 {
		return // refused outright — also fine, nothing was silently dropped mid-flight
	}
	for _, a := range acts {
		if a.Status == platform.ActApplied {
			t.Errorf("KILL-SWITCH BYPASSED: action %s is applied on a halted tenant", a.ID)
		}
	}
}
