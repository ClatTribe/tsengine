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

func TestTLSHostAllowed_ScreensPrivate(t *testing.T) {
	if tlsHostAllowed(context.Background(), "127.0.0.1") {
		t.Error("loopback must be screened out (SSRF)")
	}
	if tlsHostAllowed(context.Background(), "10.0.0.5:443") {
		t.Error("private IP must be screened out (SSRF)")
	}
}
