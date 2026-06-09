package exporter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/report"
)

var now = time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

func sampleReport() *report.Report {
	return &report.Report{
		Kind: "Web Application Penetration Test", Target: "https://app.example", Engine: "tsengine 0.1.0",
		Signed: true, Signer: "tsengine-prod-key-v1",
		Findings: []report.Finding{
			{ID: "web-001", Title: "SQL Injection", Severity: "high", Status: "verified",
				Endpoint: "https://app.example/search?q=", Tool: "webagent", CWE: []string{"CWE-89"},
				Remediation: "Use parameterized queries.", Description: "error-based SQLi"},
			{ID: "f-002", Title: "Missing security header", Severity: "low", Status: "pattern_match",
				Endpoint: "src/server.go:42", Tool: "nuclei"},
		},
	}
}

func TestToSARIF_Valid(t *testing.T) {
	data, err := ToSARIF(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	// must round-trip as valid JSON with the SARIF shape
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("version = %v", log["version"])
	}
	runs, _ := log["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "tsengine" {
		t.Errorf("driver name = %v", driver["name"])
	}
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("want 2 rules (distinct titles), got %d", len(rules))
	}
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}

	// the high+verified finding → level error, security-severity high, CWE tag, file location with line
	r0 := results[0].(map[string]any)
	if r0["level"] != "error" {
		t.Errorf("high finding level = %v, want error", r0["level"])
	}
	msg := r0["message"].(map[string]any)["text"].(string)
	if msg == "" || msg[:10] != "[verified]" {
		t.Errorf("verified finding message should be prefixed: %q", msg)
	}
	// the file:line endpoint → region with startLine 42
	r1 := results[1].(map[string]any)
	loc := r1["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if loc["artifactLocation"].(map[string]any)["uri"] != "src/server.go" {
		t.Errorf("uri = %v, want src/server.go", loc["artifactLocation"])
	}
	if loc["region"].(map[string]any)["startLine"].(float64) != 42 {
		t.Errorf("startLine wrong: %v", loc["region"])
	}

	// CWE must appear as a code-scanning tag on the rule
	full := string(data)
	if !contains(full, "external/cwe/cwe-89") || !contains(full, "security-severity") {
		t.Errorf("SARIF missing CWE tag or security-severity:\n%s", full)
	}
}

func TestWebhook_PostsSignedPayload(t *testing.T) {
	var gotBody []byte
	var gotAuth, gotSig, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotAuth = r.Header.Get("Authorization")
		gotSig = r.Header.Get("X-TSEngine-Signature")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ev := EventFromReport(sampleReport(), now)
	if ev.Source != "tsengine" || ev.Target != "https://app.example" || len(ev.Findings) != 2 {
		t.Fatalf("event built wrong: %+v", ev)
	}
	if ev.RiskRating != "High" {
		t.Errorf("risk rating = %q, want High", ev.RiskRating)
	}

	code, err := Emit(context.Background(), ev, EmitOptions{
		URL: srv.URL, Token: "soc-token", HMACSecret: "shhh", Client: srv.Client(),
	})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if code != http.StatusAccepted {
		t.Errorf("code = %d", code)
	}
	if gotCT != "application/json" || gotAuth != "Bearer soc-token" {
		t.Errorf("headers wrong: ct=%q auth=%q", gotCT, gotAuth)
	}
	// the receiver can verify the HMAC over the exact body it got
	want := "sha256=" + Sign(gotBody, "shhh")
	if gotSig != want {
		t.Errorf("signature mismatch: got %q want %q", gotSig, want)
	}
	// the payload round-trips and carries the verified finding
	var rev Event
	if err := json.Unmarshal(gotBody, &rev); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if rev.Findings[0].Status != "verified" {
		t.Errorf("verified status lost in transit")
	}
}

func TestWebhook_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := Emit(context.Background(), EventFromReport(sampleReport(), now), EmitOptions{URL: srv.URL, Client: srv.Client()})
	if err == nil {
		t.Fatal("a 500 from the webhook should be an error")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
