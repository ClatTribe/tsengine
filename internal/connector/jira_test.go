package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestJira_FileTicketCreatesIssue(t *testing.T) {
	var gotAuth, gotPath string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"SEC-1"}`))
	}))
	defer srv.Close()

	j := NewJira(srv.URL, "ops@acme.example", "api-tok", "SEC")
	j.HTTP = srv.Client()
	act := platform.Action{
		ID: "a1", FindingID: "f1", Kind: platform.ActFileTicket,
		Title: "Admin without MFA: ceo@acme", Payload: map[string]any{"summary": "Enforce MFA on ceo@acme"},
	}
	if err := j.FileTicket(context.Background(), act); err != nil {
		t.Fatal(err)
	}

	if gotPath != "/rest/api/3/issue" {
		t.Errorf("wrong endpoint: %q", gotPath)
	}
	// basic auth = base64(email:token)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops@acme.example:api-tok"))
	if gotAuth != want {
		t.Errorf("auth wrong: got %q", gotAuth)
	}
	fields, _ := body["fields"].(map[string]any)
	if fields["summary"] != "Admin without MFA: ceo@acme" {
		t.Errorf("summary wrong: %+v", fields["summary"])
	}
	if proj, _ := fields["project"].(map[string]any); proj["key"] != "SEC" {
		t.Errorf("project wrong: %+v", fields["project"])
	}
	// description must be ADF (a doc, not a bare string)
	if desc, _ := fields["description"].(map[string]any); desc["type"] != "doc" {
		t.Errorf("description should be ADF: %+v", fields["description"])
	}
}

func TestJira_Non2xxAndUnconfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	j := NewJira(srv.URL, "e", "t", "SEC")
	j.HTTP = srv.Client()
	if err := j.FileTicket(context.Background(), platform.Action{Title: "x"}); err == nil {
		t.Error("a 400 from Jira should error")
	}

	// unconfigured (no project) errors rather than silently posting nothing
	if err := (&Jira{BaseURL: "https://x", Email: "e", APIToken: "t"}).FileTicket(context.Background(), platform.Action{}); err == nil {
		t.Error("an unconfigured Jira (no project) should error")
	}
}

// the renderer must escape into JSON cleanly (no broken payloads on special chars)
func TestJira_ADFMarshals(t *testing.T) {
	b, err := json.Marshal(adf("line with \"quotes\" & <tags>"))
	if err != nil || !strings.Contains(string(b), "quotes") {
		t.Errorf("adf marshal: %s %v", b, err)
	}
}
