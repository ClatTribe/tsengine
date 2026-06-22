package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestPublicTrust_FrameworksIsEmptyArrayNotNull(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	h := NewHandler(d)

	// A fresh tenant with no posture data: the PUBLIC trust page must serialize frameworks as []
	// not null (a null crashes the customer-shared page's .map — the nil-slice → JSON-null footgun).
	tok := d.trustToken("t1")
	req := httptest.NewRequest("GET", "/v1/trust/t1?token="+tok, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid trust token should serve the page, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"frameworks":null`) {
		t.Errorf("public trust frameworks must be [] not null: %s", rec.Body.String())
	}
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if _, ok := v["frameworks"].([]any); !ok {
		t.Errorf("frameworks must be a JSON array, got %T", v["frameworks"])
	}

	// A bogus token must not leak (404).
	bogus := httptest.NewRequest("GET", "/v1/trust/t1?token=bogus", nil)
	br := httptest.NewRecorder()
	h.ServeHTTP(br, bogus)
	if br.Code != http.StatusNotFound {
		t.Errorf("a bogus trust token must 404, got %d", br.Code)
	}
}
