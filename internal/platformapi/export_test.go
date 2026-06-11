package platformapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func exportHandler(t *testing.T) (interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}, store.Store) {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutFinding(context.Background(), "t1", types.Finding{
		ID: "f1", RuleID: "nuclei::sqli", Tool: "nuclei", Severity: types.SeverityCritical,
		Title: "SQL injection", Endpoint: "https://acme/search",
	})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	return h, st
}

func TestExport_SARIFDefault(t *testing.T) {
	h, _ := exportHandler(t)
	rec := do(h, "GET", "/v1/findings/export", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/sarif+json" {
		t.Errorf("want sarif content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"$schema"`) || !strings.Contains(body, "SQL injection") {
		t.Errorf("SARIF should contain the schema + the finding, got: %s", body[:min(200, len(body))])
	}
}

func TestExport_CSV(t *testing.T) {
	h, _ := exportHandler(t)
	rec := do(h, "GET", "/v1/findings/export?format=csv", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("want csv content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "id,severity,status,tool,title,endpoint") {
		t.Error("CSV should have the header row")
	}
	if !strings.Contains(body, "f1,critical") || !strings.Contains(body, "SQL injection") {
		t.Errorf("CSV should contain the finding row, got: %s", body)
	}
}
