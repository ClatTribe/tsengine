package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestCreateAsset_AddsStandaloneTarget(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// A web target the connectors don't cover — the founder's website.
	rec := do(h, "POST", "/v1/assets", "t1", `{"type":"web_application","target":"app.acme.com","authorized":true}`)
	if rec.Code != 201 {
		t.Fatalf("valid web target should be created (201), got %d: %s", rec.Code, rec.Body.String())
	}
	var got assetView
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Target != "https://app.acme.com" { // scheme defaulted to https
		t.Errorf("target should be canonicalized to https://app.acme.com, got %q", got.Target)
	}
	if got.Type != "web_application" || got.Meta["source"] != "manual" {
		t.Errorf("asset not stored as a manual web_application: %+v", got.Asset)
	}
	assets, _ := st.ListAssets(context.Background(), "t1")
	if len(assets) != 1 {
		t.Fatalf("want 1 asset stored, got %d", len(assets))
	}

	// Idempotent: re-adding the same (type,target) returns the existing asset, not a dup.
	if r2 := do(h, "POST", "/v1/assets", "t1", `{"type":"web_application","target":"https://app.acme.com","authorized":true}`); r2.Code != 200 {
		t.Errorf("re-adding the same target should be idempotent (200), got %d", r2.Code)
	}
	if a, _ := st.ListAssets(context.Background(), "t1"); len(a) != 1 {
		t.Errorf("idempotent re-add must not create a duplicate, got %d assets", len(a))
	}
}

func TestCreateAsset_RejectsUnauthorizedAndUnsafe(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	cases := []struct {
		name, body string
		want       int
	}{
		{"no authorization attestation", `{"type":"web_application","target":"acme.com","authorized":false}`, 400},
		{"unsupported type (repo comes from a connector)", `{"type":"repository","target":"acme/app","authorized":true}`, 400},
		{"SSRF: private host", `{"type":"web_application","target":"http://10.0.0.5/admin","authorized":true}`, 400},
		{"SSRF: loopback", `{"type":"web_application","target":"http://127.0.0.1","authorized":true}`, 400},
		{"SSRF: reserved namespace", `{"type":"domain","target":"db.internal","authorized":true}`, 400},
		{"SSRF: link-local IP", `{"type":"ip_address","target":"169.254.169.254","authorized":true}`, 400},
		{"private IP target", `{"type":"ip_address","target":"192.168.1.1","authorized":true}`, 400},
		{"empty target", `{"type":"web_application","target":"  ","authorized":true}`, 400},
	}
	for _, c := range cases {
		if rec := do(h, "POST", "/v1/assets", "t1", c.body); rec.Code != c.want {
			t.Errorf("%s: want %d, got %d (%s)", c.name, c.want, rec.Code, rec.Body.String())
		}
	}
	if a, _ := st.ListAssets(context.Background(), "t1"); len(a) != 0 {
		t.Errorf("no invalid/unsafe target should have been stored, got %d assets", len(a))
	}

	// A public IP + CIDR + image are accepted.
	for _, ok := range []string{
		`{"type":"ip_address","target":"8.8.8.8","authorized":true}`, // a genuinely routable public IP (203.0.113.x is now correctly blocked as TEST-NET)
		`{"type":"container_image","target":"ghcr.io/acme/api:1.4.2","authorized":true}`,
	} {
		if rec := do(h, "POST", "/v1/assets", "t1", ok); rec.Code != 201 {
			t.Errorf("valid public target should be accepted (201), got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

func TestCreateAsset_TenantScoped(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	do(h, "POST", "/v1/assets", "t1", `{"type":"domain","target":"acme.com","authorized":true}`)
	// t2 must not see t1's asset.
	if a, _ := st.ListAssets(context.Background(), "t2"); len(a) != 0 {
		t.Errorf("tenant isolation: t2 must not see t1's asset, got %d", len(a))
	}
}

// The plan asset cap (economic gate): Free is capped, Growth expands. Over-cap → 402.
func TestCreateAsset_PlanAssetCap(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "free", Plan: platform.PlanFree})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	add := func(tid, host string) int {
		return do(h, "POST", "/v1/assets", tid, `{"type":"web_application","target":"`+host+`","authorized":true}`).Code
	}
	// Free cap is 2: the first two succeed, the third is refused with 402 (upgrade prompt).
	if c := add("free", "a.example.com"); c != 201 {
		t.Fatalf("1st free asset → 201, got %d", c)
	}
	if c := add("free", "b.example.com"); c != 201 {
		t.Fatalf("2nd free asset → 201, got %d", c)
	}
	if c := add("free", "c.example.com"); c != 402 {
		t.Fatalf("3rd free asset must be over-cap → 402, got %d", c)
	}
	// A Growth tenant can go past the Free cap.
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "paid", Plan: platform.PlanGrowth})
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if c := add("paid", host); c != 201 {
			t.Fatalf("growth tenant should add %s → 201, got %d", host, c)
		}
	}
}
