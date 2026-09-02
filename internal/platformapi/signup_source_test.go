package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
)

// Nothing could say where a workspace came from. Every GTM motion that pays a partner, measures a
// channel or watches a segment depends on attribution, so the signup keeps the `?ref=` tag it
// arrived with — bounded so it can be COUNTED, and never invented when absent.
func TestSignup_RecordsNormalizedSource(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Vanta-Marketplace", "vanta-marketplace"},
		{"  yc_w26 ", "yc_w26"},
		{"", ""},
		{"<script>alert(1)</script>", ""}, // anything outside [a-z0-9._-] is dropped, not stored raw
		{strings.Repeat("a", 100), strings.Repeat("a", 64)},
	}
	for _, c := range cases {
		if got := normalizeSource(c.in); got != c.want {
			t.Errorf("normalizeSource(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	st := store.NewMemory()
	d := Deps{Store: st, Token: "tok"}
	h := NewHandler(d)
	req := httptest.NewRequest("POST", "/v1/auth/signup", strings.NewReader(`{"workspace":"Acme","email":"a@acme.io","password":"longenough1","source":"Peak-XV-Perk"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup: want 201, got %d %s", rec.Code, rec.Body.String())
	}
	tenants, _ := st.ListTenants(context.Background())
	if len(tenants) != 1 || tenants[0].Source != "peak-xv-perk" {
		t.Fatalf("the tenant must carry the normalized source, got %+v", tenants)
	}

	// Operator onboarding carries it too (a managed / MSP tenant is attributed by whoever created it).
	req = httptest.NewRequest("POST", "/v1/tenants", strings.NewReader(`{"name":"Beta","source":"msp:northwind"}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tenant: want 201, got %d %s", rec.Code, rec.Body.String())
	}
	tenants, _ = st.ListTenants(context.Background())
	var beta string
	for _, tn := range tenants {
		if tn.Name == "Beta" {
			beta = tn.Source
		}
	}
	if beta != "" {
		t.Fatalf("a colon is outside the allowed set, so 'msp:northwind' must be dropped to direct/unknown, got %q", beta)
	}
}
