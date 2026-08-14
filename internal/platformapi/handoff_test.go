package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// T8 — hand off what isn't ours to fix.
//
// This is the only engineer tool that WRITES into the customer's queue, and at tier 1 it auto-delivers
// to their real tracker stamped raised_by:ai-security-engineer. So the bar is not "a ticket appeared" —
// it is that the ticket describes something the engine actually found, and carries what a receiver on
// another team needs to act without coming back to ask.

type capturingSubmitter struct{ got platform.Action }

func (c *capturingSubmitter) Submit(_ context.Context, a platform.Action) (platform.Action, error) {
	c.got = a
	return a, nil
}

func handoffDeps(t *testing.T, fs ...types.Finding) (Deps, *capturingSubmitter, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid}); err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := st.PutFinding(ctx, tid, f); err != nil {
			t.Fatal(err)
		}
	}
	sub := &capturingSubmitter{}
	return Deps{Store: st, Submitter: sub, NewID: func() string { return "1" }}, sub, tid
}

var vendorCVE = types.Finding{
	ID: "f-42", Tool: "grype", RuleID: "CVE-2023-9999", Severity: types.SeverityHigh,
	Title:    "Deserialization flaw in vendor SDK",
	Endpoint: "pkg:maven/com.vendor/sdk@3.1.0",
}

// THE ONE THAT MATTERS. A ticket citing a finding that does not exist must not reach the queue —
// otherwise the tool is a channel for anything the model believes, delivered to a human's tracker
// under our name and checkable by nobody.
func TestT8_RefusesATicketForAFindingThatDoesNotExist(t *testing.T) {
	d, sub, tid := handoffDeps(t, vendorCVE)
	_, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"f-does-not-exist", "Critical RCE in vendor SDK — upgrade urgently", "Reported upstream.")
	if err == nil {
		t.Fatal("T8 UNGROUNDED: a ticket was filed for a finding that does not exist — the model can " +
			"write any claim it likes into the customer's tracker under our name")
	}
	if sub.got.ID != "" {
		t.Errorf("T8 UNGROUNDED: refused but still submitted an action: %+v", sub.got)
	}
}

// A blank id is the same hole with a different shape.
func TestT8_RefusesATicketCitingNothing(t *testing.T) {
	d, sub, tid := handoffDeps(t, vendorCVE)
	if _, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"  ", "Something should be done", ""); err == nil {
		t.Error("T8 UNGROUNDED: a ticket citing no finding was accepted")
	}
	if sub.got.ID != "" {
		t.Errorf("T8 UNGROUNDED: submitted anyway: %+v", sub.got)
	}
}

// Tenant isolation (§18.2 inv. 2) has to hold on this path too: another tenant's finding id must be
// unresolvable here, not merely unauthorized.
func TestT8_CannotCiteAnotherTenantsFinding(t *testing.T) {
	ctx := context.Background()
	d, sub, tid := handoffDeps(t, vendorCVE)
	if err := d.Store.PutTenant(ctx, platform.Tenant{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.PutFinding(ctx, "other", types.Finding{ID: "f-secret", Title: "Other tenant's finding"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(ctx, "f-secret", "Handoff", ""); err == nil {
		t.Error("T8 ISOLATION: cited another tenant's finding")
	}
	if sub.got.ID != "" {
		t.Errorf("T8 ISOLATION: submitted anyway: %+v", sub.got)
	}
}

// A real finding files, and the action carries the grounding link Action.FindingID documents as
// "always set".
func TestT8_RealFindingFilesAndCarriesTheGroundingLink(t *testing.T) {
	d, sub, tid := handoffDeps(t, vendorCVE)
	ref, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"f-42", "Upgrade vendor SDK past the deserialization flaw", "Fix is upstream in 3.2.0.")
	if err != nil {
		t.Fatalf("a real finding should file: %v", err)
	}
	if ref == "" {
		t.Error("no ticket reference returned")
	}
	if sub.got.FindingID != "f-42" {
		t.Errorf("T8 UNGROUNDED: Action.FindingID is %q, want f-42 — it is documented as always set",
			sub.got.FindingID)
	}
	if sub.got.Kind != platform.ActFileTicket || sub.got.Tier != 1 {
		t.Errorf("wrong action shape: kind=%s tier=%d", sub.got.Kind, sub.got.Tier)
	}
}

// THE BAR ITSELF: "context a receiver can act on". Someone on another team who was not in the
// conversation needs what was found, how bad, where, and who said so — without coming back to ask.
func TestT8_CarriesWhatAReceiverNeedsToAct(t *testing.T) {
	d, sub, tid := handoffDeps(t, vendorCVE)
	if _, err := (ticketFiler{d: d, tenantID: tid}).FileTicket(context.Background(),
		"f-42", "Upgrade vendor SDK", "Fixed upstream in 3.2.0."); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"severity":    "high",                           // how urgent
		"location":    "pkg:maven/com.vendor/sdk@3.1.0", // where it is
		"detected_by": "grype",                          // who says so
		"rule":        "CVE-2023-9999",                  // what to look up
		"finding_id":  "f-42",                           // how to trace it back
	} {
		got, _ := sub.got.Payload[field].(string)
		if !strings.EqualFold(got, want) {
			t.Errorf("T8 NOT ACTIONABLE: payload[%q] = %q, want %q — a receiver on another team cannot "+
				"act on this without coming back to ask", field, got, want)
		}
	}
}
