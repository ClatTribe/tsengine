package platformapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The point of this endpoint is that a stranger can read it. A regression that wraps it in
// d.auth would not break any test that supplied a token, so the no-token case is the test.
func TestSampleReport_IsPublic_NoTokenNoTenantNoStore(t *testing.T) {
	// Deps deliberately ZERO: no Store, no GRC, no vault. The sample must not depend on any
	// of them — if it ever reads tenant state, this panics or errors here rather than in prod.
	var d Deps
	rec := httptest.NewRecorder()
	d.handleSampleReport(rec, httptest.NewRequest(http.MethodGet, "/v1/sample-report", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the sample report must be readable with no account", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Example Corp") {
		t.Error("body does not name the sample subject")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("default Content-Type = %q, want text/markdown", ct)
	}
}

func TestSampleReport_FormatsAndDownload(t *testing.T) {
	var d Deps
	for _, tc := range []struct{ query, wantCT, wantExt string }{
		{"", "text/markdown", ".md"},
		{"?format=html", "text/html", ".html"},
		{"?format=json", "application/json", ".json"},
	} {
		rec := httptest.NewRecorder()
		d.handleSampleReport(rec, httptest.NewRequest(http.MethodGet, "/v1/sample-report"+tc.query, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%q: status %d", tc.query, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, tc.wantCT) {
			t.Errorf("%q: Content-Type = %q, want %q", tc.query, ct, tc.wantCT)
		}
		// Without ?download the browser must RENDER it — a page that always downloads cannot
		// be linked to, and an unreadable link is a worse asset than no link.
		if cd := rec.Header().Get("Content-Disposition"); cd != "" {
			t.Errorf("%q: unexpected Content-Disposition %q without ?download", tc.query, cd)
		}

		sep := "?"
		if tc.query != "" {
			sep = "&"
		}
		rec = httptest.NewRecorder()
		d.handleSampleReport(rec, httptest.NewRequest(http.MethodGet, "/v1/sample-report"+tc.query+sep+"download=1", nil))
		cd := rec.Header().Get("Content-Disposition")
		if !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, tc.wantExt) {
			t.Errorf("%q&download=1: Content-Disposition = %q, want an attachment named %s", tc.query, cd, tc.wantExt)
		}
	}
}

// The coverage admissions have to survive the handler, not just the generator — and Reassess
// has to have run, or the report can list unscanned scope and still close by calling the
// estate clean.
func TestSampleReport_CarriesTheCoverageAdmissions(t *testing.T) {
	var d Deps
	rec := httptest.NewRecorder()
	d.handleSampleReport(rec, httptest.NewRequest(http.MethodGet, "/v1/sample-report", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"aws:123456789012",                 // the untested target, named
		"github.com/example-corp/payments", // the partially-assessed one
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered report does not mention %q — a coverage gap that is not "+
				"printed is indistinguishable from one that does not exist", want)
		}
	}
}
