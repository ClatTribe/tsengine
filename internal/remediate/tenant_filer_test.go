package remediate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

type countingFiler struct{ filed int32 }

func (r *countingFiler) FileTicket(context.Context, platform.Action) error {
	atomic.AddInt32(&r.filed, 1)
	return nil
}

// When the tenant has its own Jira config, the action is filed there (a real POST to that base),
// not the operator fallback.
func TestTenantFiler_RoutesToPerTenantJira(t *testing.T) {
	var posted int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&posted, 1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"SEC-1"}`))
	}))
	defer srv.Close()

	fallback := &countingFiler{}
	tf := TenantFiler{
		Resolve: func(_ context.Context, tenantID string) (string, string, string, string, bool) {
			if tenantID == "t1" {
				return srv.URL, "sec@acme.io", "tok", "SEC", true
			}
			return "", "", "", "", false
		},
		Fallback: fallback,
	}
	if err := tf.FileTicket(context.Background(), platform.Action{TenantID: "t1", Title: "Fix it"}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if atomic.LoadInt32(&posted) == 0 {
		t.Error("the per-tenant Jira should have been posted to")
	}
	if atomic.LoadInt32(&fallback.filed) != 0 {
		t.Error("the operator fallback must NOT fire when the tenant has its own Jira")
	}
}

// With no per-tenant Jira, the action falls through to the operator filer.
func TestTenantFiler_FallsBackToOperator(t *testing.T) {
	fallback := &countingFiler{}
	tf := TenantFiler{
		Resolve:  func(context.Context, string) (string, string, string, string, bool) { return "", "", "", "", false },
		Fallback: fallback,
	}
	if err := tf.FileTicket(context.Background(), platform.Action{TenantID: "t2", Title: "x"}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&fallback.filed) != 1 {
		t.Error("the operator fallback must fire when the tenant has no Jira")
	}
}

func TestTenantFiler_NoFallbackIsSafe(t *testing.T) {
	tf := TenantFiler{Resolve: func(context.Context, string) (string, string, string, string, bool) { return "", "", "", "", false }}
	if err := tf.FileTicket(context.Background(), platform.Action{TenantID: "x"}); err != nil {
		t.Errorf("no per-tenant Jira + no fallback should be a safe no-op, got %v", err)
	}
}
