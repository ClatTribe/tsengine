package platformapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postLead(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/lead", strings.NewReader(body))
	r.RemoteAddr = "9.9.9.9:1234"
	w := httptest.NewRecorder()
	Deps{}.handleLead(w, r)
	return w
}

func TestHandleLead(t *testing.T) {
	// valid lead → 200
	if w := postLead(`{"name":"Ada","email":"ada@acme.com","company":"Acme","source":"pricing"}`); w.Code != http.StatusOK {
		t.Errorf("valid lead → %d, want 200 (%s)", w.Code, w.Body.String())
	}
	// missing email → 400
	if w := postLead(`{"name":"Ada"}`); w.Code != http.StatusBadRequest {
		t.Errorf("missing email → %d, want 400", w.Code)
	}
	// bad email → 400
	if w := postLead(`{"name":"Ada","email":"not-an-email"}`); w.Code != http.StatusBadRequest {
		t.Errorf("bad email → %d, want 400", w.Code)
	}
	// malformed JSON → 400
	if w := postLead(`{`); w.Code != http.StatusBadRequest {
		t.Errorf("malformed body → %d, want 400", w.Code)
	}
}
