package webagent

import "testing"

func toolDefNames(ts []toolDef) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.name
	}
	return out
}

func hasName(ts []toolDef, name string) bool {
	for _, t := range ts {
		if t.name == name {
			return true
		}
	}
	return false
}

func TestSelectedTools_DefaultOnSelects(t *testing.T) {
	// Default (no env) → selection is ON: an sqli seed yields a focused subset within the cap.
	cc := &Context{Seeds: []SeedFinding{{Class: "sqli", Route: "https://x/search?q="}}}
	sel := selectedTools(cc, nil)
	if len(sel) > maxActiveTools {
		t.Errorf("default-on must cap the catalog at %d, got %d", maxActiveTools, len(sel))
	}
	if len(sel) >= len(tools()) {
		t.Errorf("default-on should focus the catalog below the full %d, got %d", len(tools()), len(sel))
	}
	if !hasName(sel, "sqli_bool_probe") {
		t.Errorf("default-on sqli seed should surface sqli_bool_probe, got %v", toolDefNames(sel))
	}
}

func TestSelectedTools_KillSwitchReturnsFullCatalog(t *testing.T) {
	// The explicit opt-out renders every tool, exactly as before selection existed.
	t.Setenv("TSENGINE_TOOL_SELECT", "0")
	sel := selectedTools(&Context{Seeds: []SeedFinding{{Class: "sqli"}}}, nil)
	if len(sel) != len(tools()) {
		t.Fatalf("TSENGINE_TOOL_SELECT=0 must return the full catalog: got %d, want %d", len(sel), len(tools()))
	}
}

func TestSelectedTools_SqliSeedFocusesCatalog(t *testing.T) {
	t.Setenv("TSENGINE_TOOL_SELECT", "1")
	cc := &Context{Seeds: []SeedFinding{{Class: "sqli", Route: "https://x/search?q=", Tool: "nuclei"}}}
	sel := selectedTools(cc, nil)

	if len(sel) > maxActiveTools {
		t.Errorf("active set %d exceeds cap %d", len(sel), maxActiveTools)
	}
	if !hasName(sel, "sqli_bool_probe") {
		t.Errorf("an sqli seed should surface sqli_bool_probe, got %v", toolDefNames(sel))
	}
	for _, gone := range []string{"jwt_crack", "ssh_exec", "graphql_introspect"} {
		if hasName(sel, gone) {
			t.Errorf("an sqli seed should NOT surface %q, got %v", gone, toolDefNames(sel))
		}
	}
	// CORE is always present regardless of the subgoal.
	for name := range coreTools {
		if !hasName(sel, name) {
			t.Errorf("core tool %q must always be active, got %v", name, toolDefNames(sel))
		}
	}
}

func TestSelectedTools_JwtFromTranscript(t *testing.T) {
	t.Setenv("TSENGINE_TOOL_SELECT", "1")
	// No seed; the current line of attack (transcript tail) mentions a JWT session token → jwt_crack.
	transcript := []string{
		"ACTION send_request(...)\nOBSERVATION: 200, cookie_set:session",
		"ACTION send_request(...)\nOBSERVATION: the session is a JWT bearer token with an admin claim; try forging it",
	}
	sel := selectedTools(&Context{}, transcript)
	if !hasName(sel, "jwt_crack") {
		t.Errorf("a JWT-token line of attack should surface jwt_crack, got %v", toolDefNames(sel))
	}
}

func TestSelectedTools_HiddenToolStillInFullRegistry(t *testing.T) {
	// The safety invariant: selection shapes the PROMPT, not callability. tools() (the source of the
	// handler registry built in Investigate) always contains every tool, so a hidden tool stays callable.
	t.Setenv("TSENGINE_TOOL_SELECT", "1")
	sel := selectedTools(&Context{Seeds: []SeedFinding{{Class: "sqli"}}}, nil)
	if hasName(sel, "race_probe") {
		t.Skip("race_probe unexpectedly surfaced for an sqli seed; pick another hidden tool to assert on")
	}
	if !hasName(tools(), "race_probe") {
		t.Error("tools() (the handler registry source) must still contain the hidden tool")
	}
}
