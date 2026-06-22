package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// a fallback alerter that records whether it fired.
type recordingAlerter struct{ fired int32 }

func (r *recordingAlerter) IncidentOpened(context.Context, platform.Incident) error {
	atomic.AddInt32(&r.fired, 1)
	return nil
}

func TestTenantRouter_PostsToPerTenantWebhookAndFallback(t *testing.T) {
	var gotPosts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&gotPosts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fallback := &recordingAlerter{}
	router := TenantRouter{
		Resolve: func(_ context.Context, tenantID string) (string, bool) {
			if tenantID == "ten-1" {
				return srv.URL, true // ten-1 has its own webhook
			}
			return "", false
		},
		Fallback: fallback,
		HTTP:     srv.Client(),
	}

	// ten-1 → posts to its own webhook AND the fallback fires.
	if err := router.IncidentOpened(context.Background(), platform.Incident{TenantID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&gotPosts) != 1 {
		t.Errorf("ten-1's own webhook should have been posted once, got %d", gotPosts)
	}
	if atomic.LoadInt32(&fallback.fired) != 1 {
		t.Errorf("the operator fallback should also fire, got %d", fallback.fired)
	}
}

func TestTenantRouter_NoPerTenantWebhookOnlyFallback(t *testing.T) {
	var gotPosts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&gotPosts, 1)
	}))
	defer srv.Close()

	fallback := &recordingAlerter{}
	router := TenantRouter{
		Resolve:  func(context.Context, string) (string, bool) { return "", false }, // no per-tenant hook
		Fallback: fallback,
		HTTP:     srv.Client(),
	}
	_ = router.IncidentOpened(context.Background(), platform.Incident{TenantID: "ten-2"})
	if atomic.LoadInt32(&gotPosts) != 0 {
		t.Error("no per-tenant webhook → no per-tenant post")
	}
	if atomic.LoadInt32(&fallback.fired) != 1 {
		t.Error("the operator fallback must still fire")
	}
}

func TestTenantRouter_NoFallbackIsSafe(t *testing.T) {
	router := TenantRouter{Resolve: func(context.Context, string) (string, bool) { return "", false }}
	if err := router.IncidentOpened(context.Background(), platform.Incident{TenantID: "x"}); err != nil {
		t.Errorf("a router with no fallback + no per-tenant hook should be a safe no-op, got %v", err)
	}
}
