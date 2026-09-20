package platformapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

// configurableConn is a connector whose OAuth app may or may not be registered.
type configurableConn struct {
	fakeConn
	kind string
	on   bool
}

func (c configurableConn) Kind() string     { return c.kind }
func (c configurableConn) Configured() bool { return c.on }

// The deployment half of the pre-outreach check: every item is a FACT read from configuration,
// each failing one names the variable that fixes it, and the verdict is only as green as the
// blocking items. It never claims something works — only that it is set.
func TestLaunchReadiness_ReportsWhatNobodySet(t *testing.T) {
	t.Setenv("TSENGINE_SALES_EMAIL", "")
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", "")
	st := store.NewMemory()
	bare := Deps{Store: st, Token: "tok", Connectors: connector.NewRegistry(configurableConn{kind: "github", on: false}), PublicURL: "http://localhost:8090", AppURL: ""}
	v := bare.launchReadiness()
	if v.Ready {
		t.Fatalf("a bare deployment must not read ready: %+v", v)
	}
	for _, key := range []string{"transactional_email", "sales_lead_delivery", "oauth_connectors", "public_urls"} {
		if !hasKey(v.Blocking, key) {
			t.Errorf("%s must be a blocking failure on a bare deployment; blocking=%v", key, v.Blocking)
		}
	}
	for _, it := range v.Items {
		if !it.OK && it.Fix == "" {
			t.Errorf("%s fails without naming the fix", it.Key)
		}
		if it.OK && it.Fix != "" {
			t.Errorf("%s passes but still carries a fix", it.Key)
		}
	}
	if !strings.Contains(v.Caveat, "not that it works") {
		t.Errorf("the verdict must say it reports configuration, not function")
	}

	// A configured deployment: mail + sales address + one OAuth app + https URLs + a corpus file.
	corpus := filepath.Join(t.TempDir(), "threat_intel.json")
	_ = os.WriteFile(corpus, []byte(`{"entries":{}}`), 0o600)
	t.Setenv("TSENGINE_SALES_EMAIL", "sales@example.com")
	t.Setenv("TSENGINE_THREAT_INTEL_CORPUS", corpus)
	good := Deps{Store: st, Token: "tok", Mailer: &captureMailer{},
		Connectors: connector.NewRegistry(configurableConn{kind: "github", on: true}, configurableConn{kind: "okta", on: false}),
		PublicURL:  "https://api.example", AppURL: "https://app.example"}
	v = good.launchReadiness()
	if !v.Ready || len(v.Blocking) != 0 {
		t.Fatalf("configured deployment must be ready, got %+v", v)
	}
	var conn readinessItem
	for _, it := range v.Items {
		if it.Key == "oauth_connectors" {
			conn = it
		}
	}
	if !strings.Contains(conn.Detail, "configured: github") || !strings.Contains(conn.Detail, "not configured: okta") {
		t.Errorf("the connector item must name both halves, got %q", conn.Detail)
	}
	// operator LLM is reported, but as informational — Free never spends operator budget by design
	for _, it := range v.Items {
		if it.Key == "operator_llm" && (it.OK || it.Blocking) {
			t.Errorf("no operator model must be reported as not-ok and NON-blocking, got %+v", it)
		}
	}

	// operator-token gated: a tenant session or a stranger gets nothing
	h := NewHandler(good)
	req := httptest.NewRequest("GET", "/v1/launch-readiness", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated: want 401/403, got %d", rec.Code)
	}
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out readinessView
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || !out.Ready {
		t.Fatalf("operator: want 200 ready, got %d %s", rec.Code, rec.Body.String())
	}
}

func hasKey(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
