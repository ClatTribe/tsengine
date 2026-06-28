package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestTLSScan_NoHostNoAssets(t *testing.T) {
	d := Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"}
	rec := do(NewHandler(d), "POST", "/v1/tls/scan", "t1", `{}`)
	if rec.Code != 200 {
		t.Fatalf("empty host + no assets → 200 with a note, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTLSResolveAllowed_ScreensPrivate(t *testing.T) {
	if _, ok := tlsResolveAllowed(context.Background(), "127.0.0.1"); ok {
		t.Error("loopback must be screened out (SSRF)")
	}
	if _, ok := tlsResolveAllowed(context.Background(), "10.0.0.5:443"); ok {
		t.Error("private IP must be screened out (SSRF)")
	}
	// a public IP literal is allowed AND returned for pinning (no re-resolution).
	if ip, ok := tlsResolveAllowed(context.Background(), "8.8.8.8"); !ok || ip == nil || ip.String() != "8.8.8.8" {
		t.Errorf("public IP must be allowed and returned for pinning, got ip=%v ok=%v", ip, ok)
	}
}
