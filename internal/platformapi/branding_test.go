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

// White-label: a partner's name reaches the outward artifacts, bounded; an empty name clears it;
// a logo must be https; and the PUBLIC trust view carries the brand plus the white-labelled bit the
// page uses to drop the product's own link.
func TestBranding_SetClearValidateAndReachTrustView(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	d := Deps{Store: st, Token: "tok"}
	h := NewHandler(d)
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/v1/settings/branding", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("X-Tenant-ID", "t1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, bad := range []string{
		`{"name":"","logo_url":"https://x.example/l.png"}`, // logo without a name = an unnamed brand
		`{"name":"Northwind","logo_url":"http://x.example/l.png"}`,
		`{"name":"Northwind","support_email":"not-an-email"}`,
		`{"name":"` + strings.Repeat("N", 65) + `"}`,
	} {
		if rec := put(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: want 400, got %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	rec := put(`{"name":" Northwind Security ","logo_url":"https://cdn.northwind.example/logo.png","support_email":"security@northwind.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Effective     string `json:"effective_name"`
		WhiteLabelled bool   `json:"white_labelled"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Effective != "Northwind Security" || !view.WhiteLabelled {
		t.Fatalf("branding view: %s", rec.Body.String())
	}
	tn, _ := st.GetTenant(context.Background(), "t1")
	if tn.Brand() != "Northwind Security" || !tn.WhiteLabelled() {
		t.Fatalf("stored tenant brand = %q", tn.Brand())
	}
	// the brand reaches the per-tenant VAPT report path and the pentest report path via tenantBrand
	if got := d.tenantBrand(httptest.NewRequest("GET", "/", nil), "t1"); got != "Northwind Security" {
		t.Fatalf("tenantBrand = %q", got)
	}
	if got := d.tenantBrand(httptest.NewRequest("GET", "/", nil), "nobody"); got != platform.DefaultBrand {
		t.Fatalf("an unreadable tenant must fall back to the product brand, got %q", got)
	}

	// clearing: an all-empty body returns to the product's brand
	rec = put(`{"name":""}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if rec.Code != http.StatusOK || view.WhiteLabelled || view.Effective != platform.DefaultBrand {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTrustView_CarriesWhiteLabel(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Token: "tok"}
	cfg := platform.TrustCenterConfig{Enabled: true}
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme",
		Branding:    &platform.Branding{Name: "Northwind Security", LogoURL: "https://cdn.northwind.example/logo.png", SupportEmail: "security@northwind.example"},
		TrustCenter: &cfg})
	h := NewHandler(d)
	tok := d.trustTokenFor("t1", cfg)
	req := httptest.NewRequest("GET", "/v1/trust/t1?token="+tok, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trust view: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"brand":"Northwind Security"`, `"brand_logo_url":"https://cdn.northwind.example/logo.png"`, `"brand_support_email":"security@northwind.example"`, `"white_labelled":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("public trust view must carry %s, got %s", want, body)
		}
	}
}
