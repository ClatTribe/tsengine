package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// roundTrip runs a sequence of JSON-RPC lines through the server and returns the decoded responses.
func roundTrip(t *testing.T, s *server, lines ...string) []response {
	t.Helper()
	var out bytes.Buffer
	_ = s.serve(strings.NewReader(strings.Join(lines, "\n")), &out)
	var got []response
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r response
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("undecodable response: %v", err)
		}
		got = append(got, r)
	}
	return got
}

func fakeEngine(t *testing.T, handler http.HandlerFunc) *server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &server{base: ts.URL, token: "tok", http: ts.Client()}
}

// A NOTIFICATION MUST GET NO REPLY. Replying to one is a protocol violation that several MCP clients
// treat as a fatal stream error — the server would look broken for a reason nothing in our logs shows.
func TestServe_NotificationGetsNoReply(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {})
	got := roundTrip(t, s,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
	)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 response (the notification must be silent), got %d", len(got))
	}
	var id int
	_ = json.Unmarshal(got[0].ID, &id)
	if id != 1 {
		t.Errorf("replied to the wrong message: id=%v", id)
	}
}

// initialize must advertise the protocol version and tools capability, or a client will not proceed.
func TestServe_InitializeAdvertisesTools(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {})
	got := roundTrip(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	raw, _ := json.Marshal(got[0].Result)
	if !strings.Contains(string(raw), protocolVersion) {
		t.Errorf("no protocol version advertised: %s", raw)
	}
	if !strings.Contains(string(raw), `"tools"`) {
		t.Errorf("tools capability not advertised: %s", raw)
	}
}

// THE SAFETY PROPERTY: no tool may take an action. A write tool reachable from a chat would bypass the
// desk, the tier policy and the ledger — and a code-fix action AUTO-APPLIES, opening a real PR.
func TestTools_AreReadOnly(t *testing.T) {
	for _, tool := range toolSchemas() {
		name, _ := tool["name"].(string)
		for _, verb := range []string{"propose", "fix_", "open_", "create", "apply", "remediate", "ticket", "run_"} {
			if strings.HasPrefix(name, verb) {
				t.Errorf("tool %q looks like an ACTION. This server is read-only on purpose: a write "+
					"reachable from a coding-agent chat bypasses the HITL desk, and a code-fix action "+
					"auto-applies — it would commit a branch and open a pull request with nobody approving.",
					name)
			}
		}
	}
}

// The catalogue must stay small. It competes for the model's attention with every other MCP server the
// developer has installed, and selection accuracy degrades with size — the same reason the L2 catalogue
// is capped.
func TestTools_CatalogueStaysSmall(t *testing.T) {
	if n := len(toolSchemas()); n > 6 {
		t.Errorf("%d tools exposed — keep this tight; a long list degrades the agent's selection accuracy "+
			"and crowds out the developer's other servers", n)
	}
}

// The estate question is the headline tool: it must reach /v1/ask and return the engine's answer.
func TestCallTool_AskReachesTheEngine(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/ask") {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("token not sent: %q", got)
		}
		_, _ = w.Write([]byte(`{"answer":"1 of 3 findings match; log4j in api"}`))
	})
	out, err := s.callTool("ask_security_estate", map[string]any{"question": "log4j"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "log4j in api") {
		t.Errorf("engine answer not returned: %q", out)
	}
}

// An empty answer must say nothing MATCHED — not be returned blank, which a model would render as an
// all-clear about the estate.
func TestCallTool_EmptyAnswerSaysNothingMatched(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"answer":"   "}`))
	})
	out, _ := s.callTool("ask_security_estate", map[string]any{"question": "x"})
	if !strings.Contains(strings.ToLower(out), "nothing") {
		t.Errorf("a blank answer was passed through as-is (%q) — a model reads that as 'you are clean'", out)
	}
}

// An empty issue list must NOT read as "you are secure" — it reflects what was scanned.
func TestCallTool_NoIssuesIsNotAnAllClear(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":0,"issues":[]}`))
	})
	out, _ := s.callTool("list_open_issues", nil)
	if !strings.Contains(strings.ToLower(out), "scanned") {
		t.Errorf("an empty issue list does not say it reflects what was SCANNED: %q", out)
	}
}

// A rejected token must say so plainly — the most common setup mistake, and an opaque 401 wastes the
// developer's time inside a coding session where they cannot see our logs.
func TestGet_UnauthorizedIsActionable(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	_, err := s.callTool("list_open_issues", nil)
	if err == nil || !strings.Contains(err.Error(), "TSENGINE_TOKEN") {
		t.Errorf("an auth failure should name the env var to fix, got: %v", err)
	}
}

// A tool failure must come back as tool CONTENT with isError, not a transport error that kills the
// session — the agent should be able to see the problem and try something else.
func TestDispatch_ToolFailureIsContentNotTransportError(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	got := roundTrip(t, s,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_open_issues","arguments":{}}}`)
	if len(got) != 1 || got[0].Error != nil {
		t.Fatalf("a failing tool became a transport error, killing the session: %+v", got)
	}
	raw, _ := json.Marshal(got[0].Result)
	if !strings.Contains(string(raw), `"isError":true`) {
		t.Errorf("failure not marked isError: %s", raw)
	}
}

// Choke points are the point of "what should I fix first" — no shared point must say so rather than
// implying there is leverage where there is none.
func TestCallTool_NoChokePointSaysSeparateWork(t *testing.T) {
	s := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":3,"choke_points":[]}`))
	})
	out, _ := s.callTool("what_should_i_fix_first", nil)
	if !strings.Contains(strings.ToLower(out), "separate") {
		t.Errorf("no-leverage case does not say the paths are separate work: %q", out)
	}
}
