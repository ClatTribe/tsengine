package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestJira_FileTicketRefStatusAndComment(t *testing.T) {
	var commented string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"10001","key":"SEC-42","self":"x"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SEC-42":
			_, _ = w.Write([]byte(`{"fields":{"status":{"name":"Won't Do","statusCategory":{"key":"done"}},
				"resolution":{"name":"Won't Do"},"resolutiondate":"2026-10-05T10:11:12.000+0000"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SEC-42/comment":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			raw, _ := json.Marshal(b)
			commented = string(raw)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	j := &Jira{BaseURL: srv.URL, Email: "e", APIToken: "t", Project: "SEC", HTTP: srv.Client()}

	ref, err := j.FileTicketRef(context.Background(), platform.Action{Title: "Fix it"})
	if err != nil || ref.Key != "SEC-42" || ref.URL != srv.URL+"/browse/SEC-42" {
		t.Fatalf("ref %+v err %v — the created key used to be thrown away", ref, err)
	}
	st, err := j.TicketStatus(context.Background(), "SEC-42")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 5, 10, 11, 12, 0, time.UTC)
	if st.Category != "done" || st.Name != "Won't Do" || st.Resolution != "Won't Do" || !st.ResolvedAt.Equal(want) {
		t.Fatalf("status parse wrong: %+v", st)
	}
	if err := j.AddComment(context.Background(), "SEC-42", "still present"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(commented, `"still present"`) || !strings.Contains(commented, `"type":"doc"`) {
		t.Fatalf("the comment must be Atlassian Document Format: %s", commented)
	}
}
