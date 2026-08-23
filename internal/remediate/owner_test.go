package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func ownedAsset(owner, team string) platform.Asset {
	a := webAsset("web_application")
	a.Owner, a.Team = owner, team
	return a
}

// THE invariant (ADR 0028 G1): an unowned asset SAYS it is unowned. The tempting default — fall back
// to the tenant owner so every ticket has an assignee — manufactures accountability: it names someone
// who never agreed to it, and it hides the fact a scoping exercise most needs to surface.
func TestPropose_UnownedAssetSaysSoRatherThanInventingAnOwner(t *testing.T) {
	f := types.Finding{ID: "f1", Title: "SQL injection", CWE: []string{"CWE-89"},
		Severity: types.SeverityHigh, Endpoint: "https://app/x"}
	act, _ := Propose(f, webAsset("web_application"), ids())

	owner, _ := act.Payload["owner"].(string)
	if !strings.Contains(owner, "UNASSIGNED") {
		t.Fatalf("an unowned asset must say so, got %q", owner)
	}
	if !strings.Contains(owner, "no route to a person") {
		t.Errorf("it must say what that COSTS, not merely that the field is empty: %q", owner)
	}
}

// When someone does own it, the ticket names them.
func TestPropose_OwnedAssetNamesTheOwner(t *testing.T) {
	f := types.Finding{ID: "f1", Title: "SQL injection", CWE: []string{"CWE-89"},
		Severity: types.SeverityHigh, Endpoint: "https://app/x"}
	for _, tc := range []struct{ owner, team, want string }{
		{"ana@acme.io", "payments", "ana@acme.io (payments)"},
		{"ana@acme.io", "", "ana@acme.io"},
		{"", "payments", "payments"},
	} {
		act, _ := Propose(f, ownedAsset(tc.owner, tc.team), ids())
		got, _ := act.Payload["owner"].(string)
		if !strings.Contains(got, tc.want) {
			t.Errorf("owner=%q team=%q: want %q in %q", tc.owner, tc.team, tc.want, got)
		}
		if strings.Contains(got, "UNASSIGNED") {
			t.Errorf("owner=%q team=%q: an owned asset must not read as unassigned", tc.owner, tc.team)
		}
	}
}

// Ownership ANNOTATES; it never gates. A finding on an unowned asset is still a finding, still
// ranked, still ticketed — ownership decides where it goes, never whether it counts.
func TestPropose_OwnershipNeverChangesWhetherAFindingIsActioned(t *testing.T) {
	f := types.Finding{ID: "f1", Title: "SQL injection", CWE: []string{"CWE-89"},
		Severity: types.SeverityHigh, Endpoint: "https://app/x"}
	unowned, ok1 := Propose(f, webAsset("web_application"), ids())
	owned, ok2 := Propose(f, ownedAsset("ana@acme.io", "payments"), ids())

	if !ok1 || !ok2 {
		t.Fatal("both must produce an action")
	}
	if unowned.Kind != owned.Kind || unowned.Tier != owned.Tier {
		t.Errorf("ownership must not change the action's kind or tier: %v/%d vs %v/%d",
			unowned.Kind, unowned.Tier, owned.Kind, owned.Tier)
	}
	if unowned.Payload["remediation_type"] != owned.Payload["remediation_type"] {
		t.Error("ownership must not change the remediation class")
	}
}

// Every branch of Propose carries it, not just the one that was convenient to edit.
func TestPropose_EveryAssetTypeCarriesTheOwnerLine(t *testing.T) {
	f := types.Finding{ID: "f1", Title: "something", Severity: types.SeverityHigh, Endpoint: "e"}
	for _, at := range []string{"repository", "cloud_account", "workspace", "web_application",
		"api", "container_image", "ip_address", "domain"} {
		a := webAsset(at)
		a.Owner = "ana@acme.io"
		act, ok := Propose(f, a, ids())
		if !ok {
			t.Errorf("%s: no action produced", at)
			continue
		}
		owner, _ := act.Payload["owner"].(string)
		if !strings.Contains(owner, "ana@acme.io") {
			// repository proposes a PR whose payload is the patch, not a ticket — a real exception,
			// asserted rather than silently tolerated.
			if at == "repository" && act.Kind == platform.ActOpenPR {
				continue
			}
			t.Errorf("%s (%v): owner missing from payload: %q", at, act.Kind, owner)
		}
	}
}
