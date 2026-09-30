package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func riskHarness(t *testing.T) (http.Handler, store.Store, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	f := types.Finding{ID: "f1", AssetID: "web", RuleID: "sqli", Endpoint: "https://app.acme.com/q", Severity: types.SeverityHigh, Title: "SQLi"}
	_ = st.PutFinding(ctx, "t1", f)
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	return h, st, crossdetect.DedupKey(f)
}

type ignoreResp struct {
	Rule                 platform.IgnoreRule `json:"rule"`
	ReviewDefaultApplied bool                `json:"review_default_applied"`
}

type issuesResp struct {
	Issues      []crossdetect.Issue            `json:"issues"`
	Ignored     int                            `json:"ignored"`
	Lapsed      int                            `json:"lapsed"`
	Acceptances map[string]platform.IgnoreRule `json:"acceptances"`
}

func TestIgnore_AcceptedRiskGetsAVisibleDefaultReviewDate(t *testing.T) {
	h, _, key := riskHarness(t)
	rec := do(h, "POST", "/v1/issues/ignore", "t1", `{"key":"`+key+`","by":"Priya"}`) // reason defaults to accepted_risk
	if rec.Code != 200 {
		t.Fatalf("ignore: %d %s", rec.Code, rec.Body)
	}
	var out ignoreResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.ReviewDefaultApplied {
		t.Fatal("the caller must be told the review date was ours — a silent default is a setting nobody chose")
	}
	days := time.Until(out.Rule.ExpiresAt).Hours() / 24
	if days < float64(platform.DefaultRiskReviewDays)-1 || days > float64(platform.DefaultRiskReviewDays)+1 {
		t.Fatalf("want a ~%d-day review date, got %.1f days", platform.DefaultRiskReviewDays, days)
	}
}

func TestIgnore_FalsePositiveHasNothingToReview(t *testing.T) {
	h, _, key := riskHarness(t)
	rec := do(h, "POST", "/v1/issues/ignore", "t1", `{"key":"`+key+`","reason":"false_positive"}`)
	var out ignoreResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || !out.Rule.ExpiresAt.IsZero() || out.ReviewDefaultApplied {
		t.Fatalf("a false positive gets no review date unless asked: %d %+v", rec.Code, out)
	}
}

func TestIgnore_ReviewDateLimits(t *testing.T) {
	h, _, key := riskHarness(t)
	for _, tc := range []struct{ body, why string }{
		{`{"key":"` + key + `","review_in_days":400}`, "more than a year away"},
		{`{"key":"` + key + `","expires_at":"2001-01-01"}`, "in the past"},
		{`{"key":"` + key + `","expires_at":"next tuesday"}`, "unparseable"},
		{`{"key":"` + key + `","review_in_days":-5}`, "negative"},
	} {
		if rec := do(h, "POST", "/v1/issues/ignore", "t1", tc.body); rec.Code != 400 {
			t.Errorf("a review date %s must be refused: got %d", tc.why, rec.Code)
		}
	}
	future := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	if rec := do(h, "POST", "/v1/issues/ignore", "t1", `{"key":"`+key+`","expires_at":"`+future+`"}`); rec.Code != 200 {
		t.Fatalf("a date 30 days out must be accepted: %d %s", rec.Code, rec.Body)
	}
}

// The point of the feature: when the review date passes, the issue comes BACK — with who accepted it
// and when that ran out — rather than staying hidden forever.
func TestIssues_LapsedAcceptanceReturnsToTheActiveList(t *testing.T) {
	h, st, key := riskHarness(t)
	_ = st.PutIgnoreRule(context.Background(), platform.IgnoreRule{TenantID: "t1", IssueKey: key, Reason: "accepted_risk",
		By: "Priya", At: time.Now().AddDate(0, 0, -100), ExpiresAt: time.Now().AddDate(0, 0, -10)})

	var active issuesResp
	_ = json.Unmarshal(do(h, "GET", "/v1/issues", "t1", "").Body.Bytes(), &active)
	if len(active.Issues) != 1 || active.Lapsed != 1 || active.Ignored != 0 {
		t.Fatalf("a lapsed acceptance must return the issue to the active list and not count as ignored: %+v", active)
	}
	if a := active.Acceptances[key]; a.By != "Priya" || a.ExpiresAt.IsZero() {
		t.Fatalf("the lapsed decision must ride along so the page can say who accepted it and when it ran out: %+v", a)
	}
	var hidden issuesResp
	_ = json.Unmarshal(do(h, "GET", "/v1/issues?show=ignored", "t1", "").Body.Bytes(), &hidden)
	if len(hidden.Issues) != 0 {
		t.Fatalf("a lapsed acceptance must not appear in the ignored view: %+v", hidden.Issues)
	}
}

// An acceptance recorded before review dates existed is NOT silently expired — it keeps suppressing and
// is shown with no review date so someone sets one.
func TestIssues_LegacyUndatedAcceptanceStillSuppressesAndIsShownAsUndated(t *testing.T) {
	h, st, key := riskHarness(t)
	_ = st.PutIgnoreRule(context.Background(), platform.IgnoreRule{TenantID: "t1", IssueKey: key, Reason: "accepted_risk", By: "Ravi", At: time.Now()})

	var active issuesResp
	_ = json.Unmarshal(do(h, "GET", "/v1/issues", "t1", "").Body.Bytes(), &active)
	if len(active.Issues) != 0 || active.Ignored != 1 {
		t.Fatalf("an undated legacy acceptance keeps suppressing: %+v", active)
	}
	var hidden issuesResp
	_ = json.Unmarshal(do(h, "GET", "/v1/issues?show=ignored", "t1", "").Body.Bytes(), &hidden)
	if a, ok := hidden.Acceptances[key]; !ok || !a.ExpiresAt.IsZero() {
		t.Fatalf("the ignored view must carry the decision so its missing review date can be shown: %+v", hidden.Acceptances)
	}
}

// Per-product exposure must agree with the issue list: a lapsed acceptance counts again.
func TestProductExposure_CountsALapsedAcceptanceAgain(t *testing.T) {
	h, st, key := riskHarness(t)
	ctx := context.Background()
	do(h, "POST", "/v1/products", "t1", `{"name":"Acme","asset_ids":["web"],"confirmed_by":"Priya"}`)
	_ = st.PutIgnoreRule(ctx, platform.IgnoreRule{TenantID: "t1", IssueKey: key, Reason: "accepted_risk", At: time.Now().AddDate(0, 0, -100), ExpiresAt: time.Now().AddDate(0, 0, -1)})
	out := decodeProducts(t, do(h, "GET", "/v1/products", "t1", "").Body.Bytes())
	if len(out.Products) != 1 || out.Products[0].Exposure.Total != 1 {
		t.Fatalf("a lapsed acceptance must count toward the product's exposure again: %+v", out.Products)
	}
}
