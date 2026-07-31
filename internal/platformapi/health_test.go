package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// brokenStore fails every GetTenant with a transport-style error (not ErrNotFound) — the
// "database is down" case a readiness probe MUST catch.
type brokenStore struct {
	store.Store
	err error
}

func (b brokenStore) GetTenant(context.Context, string) (platform.Tenant, error) {
	return platform.Tenant{}, b.err
}

func TestReadyz_HealthyStoreIsReady(t *testing.T) {
	d := Deps{Store: store.NewMemory()}
	rr := httptest.NewRecorder()
	d.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("healthy store should be ready, got %d: %s", rr.Code, rr.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ready" || body["store"] != "ok" {
		t.Fatalf("unexpected body: %v", body)
	}
}

// The whole point: a dead backend must turn the probe RED, unlike static /healthz.
func TestReadyz_BrokenStoreIsUnready(t *testing.T) {
	d := Deps{Store: brokenStore{err: errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")}}
	rr := httptest.NewRecorder()
	d.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("broken store must be 503, got %d: %s", rr.Code, rr.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "unready" {
		t.Fatalf("expected unready, got %v", body)
	}
}

// A store that answers ErrNotFound for the sentinel is REACHABLE — that is success, not failure.
// Guards against a regression where the probe treats a clean miss as an outage (which would make
// every freshly-provisioned box permanently unready).
func TestReadyz_NotFoundCountsAsReachable(t *testing.T) {
	d := Deps{Store: brokenStore{err: store.ErrNotFound}}
	rr := httptest.NewRecorder()
	d.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("ErrNotFound means the store answered — should be ready, got %d: %s", rr.Code, rr.Body)
	}
}

func TestReadyz_NilStoreIsUnready(t *testing.T) {
	rr := httptest.NewRecorder()
	Deps{}.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil store must be 503, got %d", rr.Code)
	}
}

// /healthz must stay static (liveness) — it should NOT go red just because the store is down,
// or a crash-loop probe would kill a process that is merely waiting on its database.
func TestHealthz_StaysLiveWhenStoreIsBroken(t *testing.T) {
	h := NewHandler(Deps{Store: brokenStore{err: errors.New("down")}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("liveness should stay 200 with a broken store, got %d", rr.Code)
	}
}
