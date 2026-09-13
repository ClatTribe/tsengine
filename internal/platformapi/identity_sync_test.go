package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/identitylog"
	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type apiTokens struct{}

func (apiTokens) Resolve(context.Context, platform.Connection) (string, error) { return "tok", nil }

type apiLog struct{ events []identitythreat.Event }

func (a apiLog) Fetch(context.Context, string, time.Time) (identitylog.Report, error) {
	return identitylog.Report{Provider: "okta", Fetched: len(a.events), Events: a.events}, nil
}

// The on-demand door is the pass's twin: same runner function, so a deployment without the feature
// says so (503) and a read that found a spray stores it and returns it.
func TestIdentitySync_UnwiredSaysSoAndWiredReadsAndStores(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive, SecretRef: "sealed"})

	d := Deps{Store: st}
	rec := httptest.NewRecorder()
	d.handleIdentitySync(rec, httptest.NewRequest(http.MethodPost, "/v1/identity/sync", nil), "t1")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "identity_log_unavailable") {
		t.Fatalf("unwired must be 503 identity_log_unavailable, got %d %s", rec.Code, rec.Body.String())
	}

	at := time.Now().Add(-20 * time.Minute)
	var evs []identitythreat.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, identitythreat.Event{ID: "f" + string(rune('0'+i)), User: "ada@acme.io", Type: identitythreat.EventLoginFail,
			Time: at.Add(time.Duration(i) * time.Minute), IP: "203.0.113.9"})
	}
	n := 0
	d.Runner = &runner.Service{Store: st, Tokens: apiTokens{}, NewID: func() string { n++; return "f" + string(rune('0'+n)) },
		IdentityLogFetchers: map[string]identitylog.Fetcher{platform.ConnOkta: apiLog{events: evs}}}
	rec = httptest.NewRecorder()
	d.handleIdentitySync(rec, httptest.NewRequest(http.MethodPost, "/v1/identity/sync", nil), "t1")
	if rec.Code != http.StatusOK {
		t.Fatalf("wired: %d %s", rec.Code, rec.Body.String())
	}
	var out runner.IdentityLogResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Events != 6 || len(out.Providers) != 1 {
		t.Errorf("result: %+v", out)
	}
	found := false
	for _, f := range out.Findings {
		if f.RuleID == "identitythreat::password_spray" {
			found = true
		}
	}
	if !found {
		t.Errorf("the spray was not returned: %+v", out.Findings)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) == 0 {
		t.Error("findings must be stored, not only returned")
	}

	// A wired deployment with no readable provider is 503 with the reasons, never "0 findings".
	d.Runner.IdentityLogFetchers = map[string]identitylog.Fetcher{platform.ConnM365: apiLog{}}
	rec = httptest.NewRecorder()
	d.handleIdentitySync(rec, httptest.NewRequest(http.MethodPost, "/v1/identity/sync", nil), "t1")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "identity_log_not_read") {
		t.Errorf("no provider read must be 503 identity_log_not_read, got %d %s", rec.Code, rec.Body.String())
	}
}
