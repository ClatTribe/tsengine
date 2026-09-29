package platformapi

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detectionvalidation"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/store"
)

// The full door: seed an engagement whose probe carried a canary, POST the WAF log that blocked that
// canary, then GET /v1/detection-validation and see the WAF credited with a marker-strength,
// blocked detection of a PROVEN probe.
func TestControlPlaneIngest_WAFBlocksProvenProbe(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	fired := time.Now().UTC().Add(-2 * time.Minute)
	const canary = "ts7f3a91canary"
	_ = st.PutPentest(ctx, pentest.Engagement{
		ID: "e1", TenantID: "t1", Name: "Q3 VAPT", Status: pentest.StatusComplete,
		Attempts: []pentest.AttemptRecord{{
			Target: "app.acme.com/search", Method: "exploit", Allowed: true, Proven: true,
			Canary: canary, At: fired,
		}},
	})

	wafLog := `[{"Action":"BLOCK","Timestamp":` +
		strconv.FormatInt(fired.Add(3*time.Second).UnixMilli(), 10) + `,
	  "RuleNameWithinRuleGroup":"AWS-AWSManagedRulesSQLiRuleSet",
	  "Request":{"ClientIP":"203.0.113.9","URI":"/search?q=` + canary + `%27","Method":"GET",
	    "Headers":[{"Name":"Host","Value":"app.acme.com"}]},
	  "Labels":[{"Name":"awswaf:managed:aws:sql-database:SQLi_QueryArguments"}]}]`

	rec := do(h, "POST", "/v1/control-plane/detections?source=aws_waf", "t1", wafLog)
	if rec.Code != 200 {
		t.Fatalf("ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var ing struct {
		Stored, MatchedToProbe, Blocked, ActiveCanaries int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &struct {
		Stored         *int `json:"stored"`
		MatchedToProbe *int `json:"matched_to_probe"`
		Blocked        *int `json:"blocked"`
		ActiveCanaries *int `json:"active_canaries"`
	}{&ing.Stored, &ing.MatchedToProbe, &ing.Blocked, &ing.ActiveCanaries}); err != nil {
		t.Fatal(err)
	}
	if ing.Stored != 1 || ing.MatchedToProbe != 1 || ing.Blocked != 1 || ing.ActiveCanaries != 1 {
		t.Fatalf("ingest echo wrong: %+v", ing)
	}

	// Now the detection-validation view must show the probe detected+blocked by the marker.
	rec = do(h, "GET", "/v1/detection-validation", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("detection-validation 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rep detectionvalidation.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("want 1 result, got %d: %s", len(rep.Results), rec.Body.String())
	}
	r := rep.Results[0]
	if r.Verdict != detectionvalidation.Detected || r.Strength != detectionvalidation.StrengthMarker || !r.Blocked {
		t.Fatalf("want detected/marker/blocked, got %+v", r)
	}
}

func TestControlPlaneIngest_RejectsUnknownSource(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "POST", "/v1/control-plane/detections?source=splunk", "t1", "[]")
	if rec.Code != 400 {
		t.Fatalf("unknown source must be 400, got %d", rec.Code)
	}
}

// Tenant isolation: tenant B's WAF snapshot cannot be matched to tenant A's probe canary, because
// canaries are collected per tenant.
func TestControlPlaneIngest_TenantIsolation(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()
	const canary = "tenantAsecret"
	_ = st.PutPentest(ctx, pentest.Engagement{ID: "e1", TenantID: "tA",
		Attempts: []pentest.AttemptRecord{{Canary: canary, Allowed: true, At: time.Now()}}})

	// tenant B posts a log containing tenant A's canary
	wafLog := `[{"Action":"BLOCK","Timestamp":` + strconv.FormatInt(time.Now().UnixMilli(), 10) + `,
	  "Request":{"URI":"/x?q=` + canary + `","Method":"GET","Headers":[{"Name":"Host","Value":"b.example"}]}}]`
	rec := do(h, "POST", "/v1/control-plane/detections?source=aws_waf", "tB", wafLog)
	var ing struct {
		MatchedToProbe int `json:"matched_to_probe"`
		ActiveCanaries int `json:"active_canaries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ing)
	if ing.ActiveCanaries != 0 || ing.MatchedToProbe != 0 {
		t.Fatalf("tenant B must not see tenant A canaries: %+v", ing)
	}
}
