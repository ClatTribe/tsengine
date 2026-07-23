package webagent

import "testing"

func shown(cc *Context) map[string]bool {
	m := map[string]bool{}
	for _, t := range selectTools(cc) {
		m[t.name] = true
	}
	return m
}

// TestSelectTools_EarlyEngagement: with no surface discovered, only core + recon show — the cred, lateral,
// probe, and confirm tools stay hidden, keeping the active list minimal.
func TestSelectTools_EarlyEngagement(t *testing.T) {
	cc := &Context{Target: "https://app.acme.com"}
	s := shown(cc)
	for _, want := range []string{"send_request", "list_routes", "record_finding", "finish", "discover_content"} {
		if !s[want] {
			t.Errorf("early engagement must show %q", want)
		}
	}
	for _, hidden := range []string{"ssh_exec", "jwt_crack", "confirm_exploit", "sqli_bool_probe"} {
		if s[hidden] {
			t.Errorf("early engagement must NOT show %q yet", hidden)
		}
	}
	if n := len(selectTools(cc)); n > 10 {
		t.Errorf("early tool list should be minimal (<=10), got %d", n)
	}
}

// TestSelectTools_SurfaceUnlocksProbes: once param-bearing surface exists, the differential probes + blind
// channels come online.
func TestSelectTools_SurfaceUnlocksProbes(t *testing.T) {
	cc := &Context{History: []Turn{{ID: "t-1", Method: "GET", URL: "https://app.acme.com/search?q=1", Status: 200}}}
	s := shown(cc)
	for _, want := range []string{"sqli_bool_probe", "bola_probe", "cors_probe", "dispatch_oss", "oob_url"} {
		if !s[want] {
			t.Errorf("surface with params must unlock %q", want)
		}
	}
	if s["ssh_exec"] {
		t.Error("ssh_exec must stay hidden until a credential signal appears")
	}
}

// TestSelectTools_CredSignalUnlocksLateral: a JWT/hash in evidence unlocks the crack + SSH-lateral tools.
func TestSelectTools_CredSignalUnlocksLateral(t *testing.T) {
	cc := &Context{History: []Turn{
		{ID: "t-1", Method: "GET", URL: "https://app.acme.com/api", Status: 200, RespSnippet: `{"token":"eyJhbGciOiJIUzI1NiJ9.abc.def"}`},
	}}
	s := shown(cc)
	for _, want := range []string{"jwt_crack", "crack_hash", "ssh_exec"} {
		if !s[want] {
			t.Errorf("a credential signal must unlock %q", want)
		}
	}
}

// TestSelectTools_FindingUnlocksConfirm + dispatch always has every tool (out-of-phase calls still work).
func TestSelectTools_FindingUnlocksConfirmAndDispatchIsFull(t *testing.T) {
	cc := &Context{Findings: []Finding{{ID: "f-1", Class: "sqli"}}}
	if !shown(cc)["confirm_exploit"] {
		t.Error("a recorded finding must unlock confirm_exploit")
	}
	// the full dispatch catalog still contains every tool regardless of what's shown
	all := map[string]bool{}
	for _, td := range tools() {
		all[td.name] = true
	}
	for _, must := range []string{"ssh_exec", "jwt_crack", "confirm_exploit", "sqli_bool_probe", "cors_probe"} {
		if !all[must] {
			t.Errorf("dispatch catalog must always contain %q (disclosure never removes capability)", must)
		}
	}
}
