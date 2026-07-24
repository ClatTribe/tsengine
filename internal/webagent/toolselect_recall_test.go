package webagent

import "testing"

// TestSelectedTools_GroundingRecall is the anti-regression guard for dynamic tool selection.
//
// Selection can ONLY regress the agent's recall if it hides a tool the agent NEEDS to ground a finding.
// "Need" is defined precisely by requiredIndicator (class → the deterministic indicator that grounds it)
// and by which tool PRODUCES that indicator. So: for every vuln class, when the agent is pursuing it (an
// L1 seed of that class), the default-on selection MUST surface at least one tool that can produce a
// grounding indicator for it. If this holds for every class, selection provably cannot regress grounding
// recall — a hidden specialist would fail here first.
//
// (send_request is always-on CORE and produces sql_error/sql_union/slow_response/reflected_input/
// external_redirect/file_disclosure/cmd_output/ssti_eval, so the classes grounded by those are covered
// by CORE; the entries below still assert it, documenting the coverage.)
func TestSelectedTools_GroundingRecall(t *testing.T) {
	t.Setenv("TSENGINE_TOOL_SELECT", "1") // force selection on (this is also the default)

	// class → the tools any ONE of which can produce a grounding indicator for it (from requiredIndicator
	// + the indicator producers: http.go/send_request, sqli_bool_probe, browser_render, bola_probe,
	// tamper_probe, privesc_probe, session_idor_probe, race_probe, nosqli_probe, oob_url/oob_check,
	// try_default_creds).
	grounds := map[string][]string{
		"sqli":                  {"send_request", "sqli_bool_probe"},
		"sql_injection":         {"send_request", "sqli_bool_probe"},
		"blind_sqli":            {"sqli_bool_probe"},
		"boolean_sqli":          {"sqli_bool_probe"},
		"union_sqli":            {"send_request"},
		"xss":                   {"send_request"},
		"reflected_xss":         {"send_request"},
		"dom_xss":               {"browser_render"},
		"stored_xss":            {"browser_render"},
		"open_redirect":         {"send_request"},
		"path_traversal":        {"send_request"},
		"lfi":                   {"send_request"},
		"xxe":                   {"send_request"},
		"command_injection":     {"send_request"},
		"rce":                   {"send_request"},
		"ssti":                  {"send_request"},
		"default_credentials":   {"try_default_creds", "send_request"},
		"ssrf":                  {"oob_url", "oob_check"},
		"blind_ssrf":            {"oob_url", "oob_check"},
		"idor":                  {"bola_probe", "tamper_probe", "session_idor_probe"},
		"bola":                  {"bola_probe", "tamper_probe", "session_idor_probe"},
		"mass_assignment":       {"privesc_probe", "tamper_probe"},
		"privilege_escalation":  {"privesc_probe", "tamper_probe"},
		"privesc":               {"privesc_probe", "tamper_probe"},
		"broken_access_control": {"tamper_probe"},
		"parameter_tampering":   {"tamper_probe"},
		"race_condition":        {"race_probe"},
		"toctou":                {"race_probe"},
		"nosqli":                {"nosqli_probe"},
	}

	for class, groundTools := range grounds {
		// The agent is pursuing this class: an L1 seed of that class (the strongest subgoal signal).
		sel := selectedTools(&Context{Seeds: []SeedFinding{{Class: class, Route: "https://target/x?p="}}}, nil)
		ok := false
		for _, gt := range groundTools {
			if hasName(sel, gt) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("RECALL REGRESSION: class %q needs one of %v to ground, but the default-on selection surfaced none. Got: %v",
				class, groundTools, toolDefNames(sel))
		}
	}
}

// TestSelectedTools_GroundingRecall_FromTranscript is the same guard but driven by the TRANSCRIPT signal
// (mid-engagement) rather than a seed — the agent discovered the vuln class while probing, and the tool
// it needs to ground it must surface on the next turn.
func TestSelectedTools_GroundingRecall_FromTranscript(t *testing.T) {
	t.Setenv("TSENGINE_TOOL_SELECT", "1")
	cases := []struct {
		transcript string
		need       []string
	}{
		{"OBSERVATION: a different id returned another user's email — looks like broken object level authorization / idor", []string{"bola_probe", "tamper_probe", "session_idor_probe"}},
		{"OBSERVATION: the checkout redeems the same one-time coupon twice under concurrency — a race condition", []string{"race_probe"}},
		{"OBSERVATION: the login form seems to reach a mongodb query; a $ne operator may bypass auth (nosql injection)", []string{"nosqli_probe"}},
		{"OBSERVATION: a normal user can set role=admin via mass assignment on the profile update", []string{"privesc_probe", "tamper_probe"}},
		{"OBSERVATION: the url param triggers a server-side fetch; a blind ssrf to an internal host is likely", []string{"oob_url", "oob_check"}},
	}
	for _, c := range cases {
		sel := selectedTools(&Context{}, []string{c.transcript})
		ok := false
		for _, n := range c.need {
			if hasName(sel, n) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("RECALL REGRESSION (transcript): %q needs one of %v, got %v", c.transcript, c.need, toolDefNames(sel))
		}
	}
}
