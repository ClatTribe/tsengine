package l2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fake opencode serve: POST /session → id; POST /session/{id}/message → scripted text.
func fakeOpenCode(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/session":
			n := atomic.AddInt64(&n, 1)
			_ = n
			json.NewEncoder(w).Encode(map[string]string{"id": "ses_test"})
		case strings.HasPrefix(r.URL.Path, "/session/ses_test/message"):
			w.Write([]byte(`{"parts":[{"type":"text","text":` + quote(reply) + `}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestOpenCodeClient_ToolCallParsing(t *testing.T) {
	srv := fakeOpenCode(t, "{\"tool\":\"advance_phase\",\"args\":{}}")
	c := NewOpenCodeClient(srv.URL, "opencode", "pw", "test/model")
	resp, err := c.Generate(context.Background(), "sys", []Message{{Role: RoleUser, Content: "go"}}, []ToolSchema{{Name: "advance_phase"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != "tool_use" || len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "advance_phase" {
		t.Fatalf("want one tool_use call, got %+v", resp)
	}
	if resp.ToolCalls[0].ID == "" || resp.ToolCalls[0].Args == nil {
		t.Errorf("tool call must carry id+args map, got %+v", resp.ToolCalls[0])
	}
}

func TestOpenCodeClient_TextFinishing(t *testing.T) {
	srv := fakeOpenCode(t, "here is my final answer in prose")
	c := NewOpenCodeClient(srv.URL, "opencode", "pw", "test/model")
	resp, err := c.Generate(context.Background(), "sys", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text == "" || len(resp.ToolCalls) != 0 || resp.StopReason != "stop" {
		t.Fatalf("prose must map to Text/stop, got %+v", resp)
	}
}

func TestOpenCodeClient_FencedAndProseWrappedJSON(t *testing.T) {
	srv := fakeOpenCode(t, "```json\n{\"tool\":\"finish_scan\",\"args\":{}}\n```")
	c := NewOpenCodeClient(srv.URL, "opencode", "pw", "m")
	resp, err := c.Generate(context.Background(), "s", nil, []ToolSchema{{Name: "finish_scan"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "finish_scan" {
		t.Fatalf("fenced JSON must parse to a tool call, got %+v", resp)
	}
}

func TestOpenCodeClient_ModelParts(t *testing.T) {
	c := NewOpenCodeClient("http://x", "", "", "google/gemini-2.5-flash")
	if providerOf(c.model) != "google" || modelID(c.model) != "gemini-2.5-flash" {
		t.Error("provider/model split wrong")
	}
}
