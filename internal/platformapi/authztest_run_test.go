package platformapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/apiauthz"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// idSealer is a round-trip (identity) Sealer for tests: Seal/Open are the identity function, so a
// config sealed by the setter can be re-opened by the run handler. (recordingSealer.Open returns "",
// which the run path needs to round-trip — hence a dedicated sealer here.)
type idSealer struct{}

func (idSealer) Seal(p string) (string, error) { return p, nil }
func (idSealer) Open(r string) (string, error) { return r, nil }

// bolaProber is a fake apiauthz.Prober that simulates a vulnerable object endpoint: every read
// returns 200 with the victim's private marker in the body — so BOTH identities see it, which is a
// proven BOLA bypass (attacker 2xx + victim's data).
type bolaProber struct {
	marker string
	calls  int
}

func (p *bolaProber) Do(_ context.Context, r apiauthz.Request) (apiauthz.Response, error) {
	p.calls++
	return apiauthz.Response{Status: 200, Body: `{"owner":"` + p.marker + `","amount":4200}`}, nil
}

const bolaCfg = `{
  "victim":   {"name":"victim","headers":{"Authorization":"Bearer A"}},
  "attacker": {"name":"attacker","headers":{"Authorization":"Bearer B"}},
  "operations": [{"method":"GET","url":"https://api.acme.com/invoices/42","class":"bola","marker":"victim@acme.com"}]
}`

const runConsent = `{"allow_active":true,"authorized_by":"Jane Sec (CISO)","consent":"Authorized active BOLA/BFLA test of api.acme.com per SOW-2026-01."}`

// setupConfiguredAPI stores an api asset with a sealed BOLA config and returns a handler wired with
// the given prober.
func setupConfiguredAPI(t *testing.T, prober apiauthz.Prober) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-api", TenantID: "t1", Type: "api", Target: "https://api.acme.com"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Vault: idSealer{}, AuthzProber: prober})
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test", "t1", bolaCfg); rec.Code != 200 {
		t.Fatalf("config setup should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	return h, st
}

func TestRunAuthzTest_ProvenBypassIsStored(t *testing.T) {
	prober := &bolaProber{marker: "victim@acme.com"}
	h, st := setupConfiguredAPI(t, prober)

	rec := do(h, "POST", "/v1/assets/a-api/authz-test/run", "t1", runConsent)
	if rec.Code != 200 {
		t.Fatalf("a consented, operator-enabled run should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if prober.calls == 0 {
		t.Fatal("the live prober was never invoked — the differential test did not actually run")
	}
	if !strings.Contains(rec.Body.String(), `"bypasses":1`) {
		t.Errorf("expected exactly one proven bypass, got: %s", rec.Body.String())
	}
	// The finding must be persisted so it flows into issues/incidents/grc.
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("the proven BOLA bypass should be stored as a finding, got %d", len(fs))
	}
	if fs[0].RuleID != "apiauthz::bola" {
		t.Errorf("stored finding should be a BOLA finding, got rule %q", fs[0].RuleID)
	}
	// The response must not echo the identities' auth headers.
	if strings.Contains(rec.Body.String(), "Bearer") {
		t.Error("the run response must NOT echo the identities' auth headers")
	}
}

func TestRunAuthzTest_ConsentGate(t *testing.T) {
	prober := &bolaProber{marker: "victim@acme.com"}
	h, _ := setupConfiguredAPI(t, prober)

	// Missing consent triplet → 403, and the prober must never fire.
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test/run", "t1", `{"allow_active":true}`); rec.Code != 403 {
		t.Errorf("a run without full consent should 403, got %d", rec.Code)
	}
	if prober.calls != 0 {
		t.Error("no probe should fire without consent")
	}
}

func TestRunAuthzTest_OperatorGate(t *testing.T) {
	// No AuthzProber wired (operator did not enable active testing) → 403 even with full consent.
	h, _ := setupConfiguredAPI(t, nil)
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test/run", "t1", runConsent); rec.Code != 403 {
		t.Errorf("a run with active testing disabled should 403, got %d", rec.Code)
	}
}

func TestRunAuthzTest_NotConfigured(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutAsset(context.Background(), platform.Asset{ID: "a-api", TenantID: "t1", Type: "api"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Vault: idSealer{}, AuthzProber: &bolaProber{}})
	if rec := do(h, "POST", "/v1/assets/a-api/authz-test/run", "t1", runConsent); rec.Code != 400 {
		t.Errorf("running an asset with no configured test should 400, got %d", rec.Code)
	}
}
