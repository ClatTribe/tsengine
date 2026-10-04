package notify

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestIncidentMessage_RoutesToTheOwner(t *testing.T) {
	text := func(inc platform.Incident) string {
		// Read the mrkdwn the channel renders, not the JSON bytes (which escape < and >).
		blocks, _ := incidentMessage(inc)["blocks"].([]any)
		sec, _ := blocks[0].(map[string]any)
		txt, _ := sec["text"].(map[string]any)
		s, _ := txt["text"].(string)
		return s
	}
	base := platform.Incident{Title: "SQL injection", RuleID: "nuclei::sqli", Severity: "critical"}

	withID := base
	withID.AssetID, withID.Owner, withID.Team, withID.OwnerSlackID = "a", "priya@acme.com", "payments", "U012ABCDEF"
	if s := text(withID); !strings.Contains(s, "<@U012ABCDEF>") || !strings.Contains(s, "priya@acme.com (payments)") {
		t.Errorf("an owner with a Slack member id must be @mentioned and named: %s", s)
	}
	named := withID
	named.OwnerSlackID = ""
	if s := text(named); strings.Contains(s, "<@") || !strings.Contains(s, "priya@acme.com") {
		t.Errorf("without a member id the owner is named, never a guessed mention: %s", s)
	}
	unowned := base
	unowned.AssetID, unowned.AssetTarget = "a", "https://old.acme.com"
	if s := text(unowned); !strings.Contains(s, "unassigned") || !strings.Contains(s, "old.acme.com") {
		t.Errorf("an unowned asset must say so and name the asset: %s", s)
	}
	if s := text(base); strings.Contains(s, "Owner") {
		t.Errorf("an incident with no asset must say nothing about ownership (unknown is not unowned): %s", s)
	}
}
