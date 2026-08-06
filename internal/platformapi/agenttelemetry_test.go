package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func telemetryHandler(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	return NewHandler(Deps{Store: st, Token: "platform-tok", NewID: func() string { return "agt" }}), st
}

func postNDJSON(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/telemetry", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer platform-tok")
	req.Header.Set("X-Tenant-ID", "t1")
	req.Header.Set("Content-Type", "application/x-ndjson")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The live-collector path: raw ADR Sensor JSONL in, grounded findings out, no hand-written inventory.
func TestAgentTelemetry_IngestsADRSensorJSONL(t *testing.T) {
	h, st := telemetryHandler(t)
	body := `{"timestamp":"2026-08-05T10:00:00Z","source":"claude","session_id":"s1","username":"ada@acme.io","hostname":"ada-mbp","model":"claude-opus-4-5","chat_history":[{"role":"assistant","tools":[{"tool_name":"query","tool_type":"mcp_tool","server_name":"postgres-mcp"}]}]}
{"timestamp":"2026-08-05T11:00:00Z","source":"cursor","session_id":"c1","username":"bob@acme.io","hostname":"bob-linux","model":"gpt-5"}`

	rec := postNDJSON(h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var resp struct {
		Agents       int `json:"agents"`
		Events       int `json:"events"`
		Skipped      int `json:"skipped_lines"`
		IssuesDetect int `json:"issues_detected"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Agents != 2 || resp.Events != 2 {
		t.Fatalf("want 2 agents from 2 events, got agents=%d events=%d", resp.Agents, resp.Events)
	}
	// The estate is unsanctioned + the MCP server unpinned/unverified, so posture findings must exist
	// and must have been stored — this proves the collector path reaches the same store as the manual one.
	if resp.IssuesDetect == 0 {
		t.Fatal("an ungoverned agent estate should produce findings")
	}
	stored, err := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != resp.IssuesDetect {
		t.Fatalf("findings not persisted: reported %d, stored %d", resp.IssuesDetect, len(stored))
	}
}

// One corrupt record from one laptop must not discard a fleet export — and the count must be
// REPORTED, so a partial estate is never mistaken for a clean one.
func TestAgentTelemetry_ReportsSkippedLines(t *testing.T) {
	h, _ := telemetryHandler(t)
	body := `{"timestamp":"2026-08-05T10:00:00Z","source":"claude","session_id":"s1","username":"ada","hostname":"h"}
this line is corrupt
{"no_source":"here"}`

	rec := postNDJSON(h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (good records still ingest), got %d: %s", rec.Code, rec.Body)
	}
	var resp struct {
		Agents  int `json:"agents"`
		Events  int `json:"events"`
		Skipped int `json:"skipped_lines"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Events != 1 || resp.Agents != 1 {
		t.Fatalf("the good record must still ingest: events=%d agents=%d", resp.Events, resp.Agents)
	}
	if resp.Skipped != 2 {
		t.Fatalf("skipped count must be reported, got %d want 2", resp.Skipped)
	}
}

// Empty/garbage input must be an explicit error, never a silent 200 that reads as "no agents found"
// — which an operator would mistake for a clean estate.
func TestAgentTelemetry_EmptyInputIsAnHonestError(t *testing.T) {
	h, _ := telemetryHandler(t)
	rec := postNDJSON(h, "not json\nalso not json\n")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unparseable telemetry, got %d: %s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["reason"] != "empty_telemetry" {
		t.Errorf("want a machine-readable reason, got %v", body)
	}
	if body["skipped_lines"] == nil {
		t.Error("must report how many lines were rejected — 'no agents' must never look clean")
	}
}
