package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The kill-switch ENFORCEMENT was already correct — nothing scans while halted. What was wrong was
// what the customer was told.
//
// Found by running it: with the switch ON, "Scan now" returned a job that finished instantly with
// status "done" and assets_scanned:0 — which reads as "it ran, nothing to do". The IDENTICAL request
// with the switch OFF honestly returned "failed". So the one path that refused to do the work was
// the one that looked successful.

// countingScanner records whether the engine was actually reached. Deps.Runner is a concrete
// *runner.Service, so the observation point is the scanner it drives rather than a stubbed runner.
type countingScanner struct{ scans *int }

func (c countingScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	*c.scans++
	return nil, nil
}

func haltDeps(t *testing.T, halted bool) (Deps, *int) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme", AgentsHalted: halted}); err != nil {
		t.Fatal(err)
	}
	// An asset to scan, so "the engine was never reached" cannot be explained by an empty estate.
	if err := st.PutAsset(ctx, platform.Asset{
		ID: "a1", TenantID: "t1", Type: "web_application", Target: "https://acme.io"}); err != nil {
		t.Fatal(err)
	}
	scans := 0
	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(),
		Scanner: countingScanner{scans: &scans}}
	return Deps{Store: st, Runner: svc}, &scans
}

func rescan(t *testing.T, d Deps) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	d.handleRescan(w, httptest.NewRequest(http.MethodPost, "/v1/rescan", nil), "t1")
	return w
}

// A halted workspace is TOLD, and no scan is attempted.
func TestRescan_HaltedIsRefusedWithAReason(t *testing.T) {
	d, scans := haltDeps(t, true)
	w := rescan(t, d)

	if w.Code == http.StatusOK || w.Code == http.StatusAccepted {
		t.Fatalf("a halted workspace got %d — the customer is handed a result that reads as a "+
			"successful scan when nothing ran", w.Code)
	}
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["code"] != "automation_halted" {
		t.Errorf("no machine-readable reason, so the UI cannot explain it: %v", body)
	}
	if body["error"] == "" {
		t.Error("no human-readable reason")
	}
	if *scans != 0 {
		t.Errorf("the engine was reached %d times while halted", *scans)
	}
}

// And a normal workspace still scans — the guard must not break the ordinary path.
func TestRescan_NotHaltedStillScans(t *testing.T) {
	d, scans := haltDeps(t, false)
	if w := rescan(t, d); w.Code != http.StatusOK {
		t.Fatalf("an un-halted workspace got %d, want 200", w.Code)
	}
	if *scans != 1 {
		t.Errorf("the engine ran %d times, want 1", *scans)
	}
}

// A store error must NOT be read as halted. §18.2 inv. 7 makes the switch fail closed where it
// matters (the desk refuses every apply, the runner pauses); this path only decides whether to
// EXPLAIN a refusal, so inventing a halt on a transient error would lock a tenant out of scanning
// for a reason that does not exist.
func TestRescan_ReadErrorDoesNotInventAHalt(t *testing.T) {
	d, scans := haltDeps(t, false)
	d.Store = missingTenantStore{d.Store}
	if w := rescan(t, d); w.Code == http.StatusConflict {
		t.Fatal("a store error was reported to the customer as an active kill-switch")
	}
	if *scans != 1 {
		t.Errorf("a transient read error blocked scanning (engine reached %d times)", *scans)
	}
}

// missingTenantStore fails every tenant read, leaving the rest of the store intact.
type missingTenantStore struct{ store.Store }

func (m missingTenantStore) GetTenant(context.Context, string) (platform.Tenant, error) {
	return platform.Tenant{}, store.ErrNotFound
}
