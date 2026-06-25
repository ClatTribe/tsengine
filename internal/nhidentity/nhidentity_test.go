package nhidentity

import "testing"

func TestClassify(t *testing.T) {
	grants := []Grant{
		// AI agent with write/admin → HIGH (the agentic over-privilege risk)
		{App: "ChatGPT Atlas", Scopes: []string{"gmail.modify", "drive.readwrite"}, Users: 3, Admin: false, Verified: true},
		// Automation (Zapier) with admin → HIGH
		{App: "Zapier", Scopes: []string{"admin.directory.user"}, Users: 1, Admin: true, Verified: true},
		// Unverified integration with write → HIGH (unverified + write)
		{App: "SomeNewTool", Scopes: []string{"files.write"}, Users: 1, Admin: false, Verified: false},
		// Verified integration, read-only → LOW
		{App: "Calendly", Scopes: []string{"calendar.readonly"}, Users: 40, Admin: false, Verified: true},
		// AI agent, read-only → LOW
		{App: "Otter.ai", Scopes: []string{"meetings.read"}, Users: 5, Admin: false, Verified: true},
	}
	ids, sum := Classify(grants)

	if sum.Total != 5 || sum.AIAgents != 2 || sum.Automations != 1 {
		t.Fatalf("summary counts off: %+v", sum)
	}
	if sum.Risky != 3 {
		t.Errorf("want 3 high-risk, got %d", sum.Risky)
	}
	if sum.WriteOrAdmin != 3 {
		t.Errorf("want 3 write/admin, got %d", sum.WriteOrAdmin)
	}
	// risk-first sort: the first id must be high risk
	if ids[0].Risk != "high" {
		t.Errorf("list should be risk-first, got %q first", ids[0].Risk)
	}
	// spot-check classifications
	by := map[string]Identity{}
	for _, i := range ids {
		by[i.Name] = i
	}
	if by["ChatGPT Atlas"].Class != "ai_agent" || by["ChatGPT Atlas"].Risk != "high" {
		t.Errorf("ChatGPT should be high-risk ai_agent, got %+v", by["ChatGPT Atlas"])
	}
	if by["Zapier"].Class != "automation" || by["Zapier"].Privilege != "admin" {
		t.Errorf("Zapier should be admin automation, got %+v", by["Zapier"])
	}
	if by["SomeNewTool"].Risk != "high" {
		t.Errorf("unverified+write should be high, got %+v", by["SomeNewTool"])
	}
	if by["Calendly"].Risk != "low" || by["Calendly"].Privilege != "read" {
		t.Errorf("Calendly should be low/read, got %+v", by["Calendly"])
	}
}
