package platformapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestProtect_PostureOverEvents(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.PutRuntimeEvent(ctx, platform.RuntimeEvent{ID: "r1", TenantID: "t1", App: "api", AttackKind: "sql_injection", Endpoint: "/search", Blocked: true, Source: "zen", OccurredAt: now})
	_ = st.PutRuntimeEvent(ctx, platform.RuntimeEvent{ID: "r2", TenantID: "t1", App: "api", AttackKind: "xss", Endpoint: "/p", Blocked: false, Source: "zen", OccurredAt: now})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	rec := do(h, "GET", "/v1/protect", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"active":true`) || !strings.Contains(out, `"blocked":1`) || !strings.Contains(out, `"monitor_only":1`) {
		t.Errorf("posture roll-up wrong: %s", out)
	}
	if !strings.Contains(out, "zen") || !strings.Contains(out, "sql_injection") {
		t.Errorf("should surface sensor + attack kind: %s", out)
	}
}

// Grounded §10: no events → not protected, just no signal.
func TestProtect_NoSignal(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/protect", "t1", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"active":false`) {
		t.Fatalf("no events must read active:false, got %d: %s", rec.Code, rec.Body.String())
	}
}
