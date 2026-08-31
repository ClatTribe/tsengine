package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/funnel"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func funnelReport(t *testing.T, d Deps, query string) funnel.Report {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleFunnel(rec, httptest.NewRequest(http.MethodGet, "/v1/funnel"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("funnel: %d %s", rec.Code, rec.Body.String())
	}
	var r funnel.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return r
}

func stageOf(t *testing.T, r funnel.Report, key string) funnel.Stage {
	t.Helper()
	for _, s := range r.Stages {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("no stage %q", key)
	return funnel.Stage{}
}

// The funnel aggregates across every tenant, so it MUST be operator-gated. A tenant session
// reaching it would be a cross-tenant read (§18.2 invariant 2).
func TestFunnel_OperatorGated(t *testing.T) {
	d := Deps{Store: store.NewMemory(), Token: "op-token"}
	h := d.platformAuth(d.handleFunnel)

	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/v1/funnel", nil))
	if w.Code == http.StatusOK {
		t.Error("the funnel served a request with NO token — it aggregates every tenant")
	}

	w = httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodGet, "/v1/funnel", nil)
	bad.Header.Set("Authorization", "Bearer not-the-operator")
	h(w, bad)
	if w.Code == http.StatusOK {
		t.Error("the funnel served a request with the WRONG token")
	}

	w = httptest.NewRecorder()
	ok := httptest.NewRequest(http.MethodGet, "/v1/funnel", nil)
	ok.Header.Set("Authorization", "Bearer op-token")
	h(w, ok)
	if w.Code != http.StatusOK {
		t.Errorf("the operator token was refused: %d %s", w.Code, w.Body.String())
	}
}

func TestFunnel_CountsEachStageFromRealState(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Now().UTC()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	// full activation: connected, has a finding, brought their own LLM
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", CreatedAt: ago(72 * time.Hour), LLM: &platform.LLMConfig{Provider: "anthropic"}})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Status: platform.ConnActive, CreatedAt: ago(71 * time.Hour)})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Severity: types.SeverityHigh, DiscoveredAt: ago(70 * time.Hour)})

	// connected, no finding, no agent
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t2", CreatedAt: ago(48 * time.Hour)})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c2", TenantID: "t2", Status: platform.ConnActive, CreatedAt: ago(47 * time.Hour)})

	// signed up only — and a REVOKED connection, which must not count as progress
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t3", CreatedAt: ago(24 * time.Hour)})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c3", TenantID: "t3", Status: platform.ConnRevoked, CreatedAt: ago(23 * time.Hour)})

	r := funnelReport(t, Deps{Store: st, Token: "op"}, "?days=30")

	for _, tc := range []struct {
		key  string
		want int
	}{
		{funnel.StageSignup, 3},
		{funnel.StageConnect, 2}, // t3's revoked connection is not progress
		{funnel.StageFirstFinding, 1},
		{funnel.StageAgentEnabled, 1},
	} {
		if got := stageOf(t, r, tc.key).Count; got != tc.want {
			t.Errorf("%s = %d, want %d", tc.key, got, tc.want)
		}
	}
}

// A tenant who signed up before the window is not in the cohort, and their activation must
// not leak into it — that would inflate every rate.
func TestFunnel_WindowSelectsTheSignupCohort(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = st.PutTenant(ctx, platform.Tenant{ID: "old", CreatedAt: now.AddDate(0, 0, -200)})
	_ = st.PutConnection(ctx, platform.Connection{ID: "co", TenantID: "old", Status: platform.ConnActive, CreatedAt: now.Add(-time.Hour)})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "new", CreatedAt: now.Add(-2 * time.Hour)})

	r := funnelReport(t, Deps{Store: st, Token: "op"}, "?days=7")
	if got := stageOf(t, r, funnel.StageSignup).Count; got != 1 {
		t.Errorf("signup = %d, want 1 (only the in-window tenant)", got)
	}
	if got := stageOf(t, r, funnel.StageConnect).Count; got != 0 {
		t.Errorf("connect = %d, want 0 — an out-of-cohort tenant's connection leaked in", got)
	}

	// Widen the window and the old tenant joins the cohort, bringing its connection.
	wide := funnelReport(t, Deps{Store: st, Token: "op"}, "?days=365")
	if got := stageOf(t, wide, funnel.StageSignup).Count; got != 2 {
		t.Errorf("wide signup = %d, want 2", got)
	}
	if got := stageOf(t, wide, funnel.StageConnect).Count; got != 1 {
		t.Errorf("wide connect = %d, want 1", got)
	}
}

// An empty platform must not read as total drop-off, and it must not read as zero scans
// either. This is the state every deployment is in on day one, so it is the most likely
// thing anyone actually sees.
func TestFunnel_EmptyPlatformReportsUnknownNotFailure(t *testing.T) {
	r := funnelReport(t, Deps{Store: store.NewMemory(), Token: "op"}, "")
	for _, x := range r.Rates {
		if x.Measured {
			t.Errorf("rate %s→%s claims a number on an empty platform", x.From, x.To)
		}
	}
	if !strings.Contains(r.Cohort, "Not activity within the window") {
		t.Error("the report does not declare that it is a signup cohort")
	}
}

// The scan counter must be honest about resetting on restart — a since-boot number read as a
// lifetime one is a wrong denominator for the whole funnel.
func TestFunnel_ScanCountDeclaresItIsSinceBoot(t *testing.T) {
	before := publicAssessCount.Load()
	publicAssessCount.Add(3)
	defer publicAssessCount.Store(before)

	s := stageOf(t, funnelReport(t, Deps{Store: store.NewMemory(), Token: "op"}, ""), funnel.StageFreeScan)
	if s.Count != int(before)+3 {
		t.Errorf("free_scan = %d, want %d", s.Count, before+3)
	}
	low := strings.ToLower(s.Basis)
	if !strings.Contains(low, "restart") || !strings.Contains(low, "tsengine_public_assess_total") {
		t.Errorf("basis does not disclose the reset or name the durable series: %q", s.Basis)
	}
}

func TestFunnel_RejectsNonsenseWindows(t *testing.T) {
	d := Deps{Store: store.NewMemory(), Token: "op"}
	for _, q := range []string{"?days=0", "?days=-5", "?days=abc", "?days=99999"} {
		rec := httptest.NewRecorder()
		d.handleFunnel(rec, httptest.NewRequest(http.MethodGet, "/v1/funnel"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", q, rec.Code)
		}
	}
}
