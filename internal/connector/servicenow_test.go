package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestServiceNow_FileTicket(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"number":"INC0012345"}}`))
	}))
	defer srv.Close()

	sn := &ServiceNow{InstanceURL: srv.URL, User: "svc", Password: "pw", HTTP: srv.Client()}
	a := platform.Action{
		Title: "enforce MFA for admin alice@acme.com", FindingID: "f-1",
		Payload: map[string]any{"summary": "Require MFA for the admin immediately."},
	}
	if err := sn.FileTicket(context.Background(), a); err != nil {
		t.Fatalf("file ticket: %v", err)
	}
	if gotPath != "/api/now/table/incident" {
		t.Errorf("path: got %q", gotPath)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:pw"))
	if gotAuth != wantAuth {
		t.Errorf("auth: got %q", gotAuth)
	}
	if gotBody["short_description"] != a.Title || gotBody["category"] != "security" {
		t.Errorf("body wrong: %v", gotBody)
	}
}

func TestServiceNow_NotConfigured(t *testing.T) {
	sn := &ServiceNow{}
	if err := sn.FileTicket(context.Background(), platform.Action{}); err == nil {
		t.Error("unconfigured ServiceNow should error")
	}
}

func TestServiceNow_SurfacesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	sn := &ServiceNow{InstanceURL: srv.URL, User: "x", Password: "y", HTTP: srv.Client()}
	if err := sn.FileTicket(context.Background(), platform.Action{Title: "t"}); err == nil {
		t.Error("401 must surface as an error")
	}
}
