package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestAttackPaths_CorrelatesCrossSurfaceAndIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()

	// Tenant t1: a web leak of an AWS key + a cloud admin finding naming the same
	// key → one cross-surface attack path.
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-cloud", TenantID: "t1", Type: "cloud_account", Target: "aws:123456789012"})
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-web", Tool: "nuclei", Severity: types.SeverityHigh,
		Title: "Exposed .env leaks credentials", Endpoint: "https://app.acme.com/.env",
		Description: "Response body contained AKIAIOSFODNN7EXAMPLE",
	})
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-cloud", Tool: "prowler", Severity: types.SeverityHigh,
		Title:       "IAM access key has AdministratorAccess",
		Description: "Access key AKIAIOSFODNN7EXAMPLE attached to a role with AdministratorAccess",
	})

	// Tenant t2: must never appear in t1's attack paths.
	_ = st.PutFinding(ctx, "t2", types.Finding{
		ID: "f-other", Tool: "prowler", Severity: types.SeverityCritical,
		Title: "OTHER-TENANT admin role", Description: "AKIAIOSFODNN7EXAMPLE",
	})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	rec := do(h, "GET", "/v1/attack-paths", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// A chain was found, crossing web → cloud, citing the AWS-key bridge.
	if !strings.Contains(body, "\"count\":1") && !strings.Contains(body, "\"count\": 1") {
		t.Errorf("expected exactly one attack path, got: %s", body)
	}
	if !strings.Contains(body, "web_application") || !strings.Contains(body, "cloud_account") {
		t.Errorf("chain should cross web → cloud, got: %s", body)
	}
	if !strings.Contains(body, "aws_key") {
		t.Errorf("chain should cite the bridging AWS-key entity, got: %s", body)
	}
	if strings.Contains(body, "OTHER-TENANT") {
		t.Error("tenant isolation breached: another tenant's finding leaked into attack paths")
	}
}

func TestIssues_DedupesSameCVEAcrossScanners(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "1", RuleID: "trivy::CVE-2021-44228", Tool: "trivy", Severity: types.SeverityCritical, Title: "Log4Shell"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "2", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical, Title: "log4j RCE"})
	_ = st.PutFinding(ctx, "t2", types.Finding{ID: "9", RuleID: "trivy::CVE-2021-44228", Tool: "trivy", Severity: types.SeverityCritical, Title: "OTHER-TENANT"})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/issues", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "\"count\":1") && !strings.Contains(body, "\"count\": 1") {
		t.Errorf("two CVE findings should collapse to one issue, got: %s", body)
	}
	if !strings.Contains(body, "\"confirmed\":1") && !strings.Contains(body, "\"confirmed\": 1") {
		t.Errorf("the merged issue should be confirmed (2 tools), got: %s", body)
	}
	if !strings.Contains(body, "trivy") || !strings.Contains(body, "grype") {
		t.Errorf("issue should list both source scanners, got: %s", body)
	}
	if strings.Contains(body, "OTHER-TENANT") {
		t.Error("tenant isolation breached in /v1/issues")
	}
}

func TestIssues_IgnoreSuppressesThenUnignoreRestores(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	// Two distinct issues for t1.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "1", RuleID: "trivy::CVE-2021-44228", Tool: "trivy", Severity: types.SeverityCritical, Title: "Log4Shell"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "2", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh, Title: "SQLi", Endpoint: "app.go:9"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// Find the CVE issue's key from the default list.
	var resp struct {
		Issues []struct {
			Key   string `json:"key"`
			Title string `json:"title"`
		} `json:"issues"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(do(h, "GET", "/v1/issues", "t1", "").Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 2 {
		t.Fatalf("want 2 issues initially, got %d", resp.Count)
	}
	var key string
	for _, i := range resp.Issues {
		if strings.Contains(i.Title, "Log4Shell") {
			key = i.Key
		}
	}
	if key == "" {
		t.Fatal("could not find the Log4Shell issue key")
	}

	// Ignore it.
	ig := do(h, "POST", "/v1/issues/ignore", "t1", `{"key":"`+key+`","reason":"accepted_risk","by":"alice"}`)
	if ig.Code != 200 {
		t.Fatalf("ignore failed: %d %s", ig.Code, ig.Body.String())
	}
	// Default list now hides it (1 left); ?show=ignored shows exactly it.
	def := do(h, "GET", "/v1/issues", "t1", "").Body.String()
	if strings.Contains(def, "Log4Shell") {
		t.Error("ignored issue should be hidden from the default list")
	}
	shown := do(h, "GET", "/v1/issues?show=ignored", "t1", "").Body.String()
	if !strings.Contains(shown, "Log4Shell") {
		t.Error("?show=ignored should reveal the suppressed issue")
	}

	// Tenant isolation: another tenant cannot see t1's ignore rule effect.
	if rules, _ := st.ListIgnoreRules(ctx, "t2"); len(rules) != 0 {
		t.Error("ignore rule leaked across tenants")
	}

	// Unignore restores it.
	un := do(h, "POST", "/v1/issues/unignore", "t1", `{"key":"`+key+`"}`)
	if un.Code != 200 {
		t.Fatalf("unignore failed: %d", un.Code)
	}
	if !strings.Contains(do(h, "GET", "/v1/issues", "t1", "").Body.String(), "Log4Shell") {
		t.Error("unignored issue should return to the default list")
	}
}

func TestAttackPaths_EmptyTenantReturnsEmptyNotNull(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/attack-paths", "empty", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	// Must be an empty array, never null (the frontend maps over it).
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("empty tenant should return an empty array, got: %s", rec.Body.String())
	}
}

func TestExclusions_FilterIssuesAndCRUD(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	// Two findings: a lodash CVE (noise the tenant wants gone) + a real app SQLi.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Tool: "trivy", RuleID: "trivy::CVE-2021-23337",
		Severity: types.SeverityHigh, Title: "lodash flaw", ToolArgs: map[string]string{"pkg": "lodash"}})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f2", Tool: "semgrep", RuleID: "semgrep::js::sqli",
		Severity: types.SeverityHigh, Title: "SQLi", Endpoint: "src/db.js"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		NewID: func() string { return "x" }})

	// Baseline: both issues present.
	if b := do(h, "GET", "/v1/issues", "t1", "").Body.String(); !strings.Contains(b, "lodash") || !strings.Contains(b, "SQLi") {
		t.Fatalf("baseline should show both issues: %s", b)
	}

	// Add an exclusion for the lodash package.
	add := do(h, "POST", "/v1/exclusions", "t1", `{"field":"package","pattern":"lodash","reason":"dev-only dep"}`)
	if add.Code != 200 {
		t.Fatalf("add exclusion: %d %s", add.Code, add.Body.String())
	}
	var created platform.ExclusionRule
	_ = json.Unmarshal(add.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("exclusion should get an id")
	}

	// Now the lodash issue is gone, the SQLi remains, and excluded=1 is reported.
	body := do(h, "GET", "/v1/issues", "t1", "").Body.String()
	if strings.Contains(body, "lodash") {
		t.Errorf("excluded package should not appear: %s", body)
	}
	if !strings.Contains(body, "SQLi") {
		t.Errorf("non-excluded finding should remain: %s", body)
	}
	if !strings.Contains(body, `"excluded":1`) {
		t.Errorf("excluded count should be 1: %s", body)
	}

	// It's listed; an invalid field is rejected.
	if l := do(h, "GET", "/v1/exclusions", "t1", "").Body.String(); !strings.Contains(l, "lodash") {
		t.Errorf("exclusion not listed: %s", l)
	}
	if bad := do(h, "POST", "/v1/exclusions", "t1", `{"field":"nope","pattern":"x"}`); bad.Code != 400 {
		t.Errorf("invalid field should be 400, got %d", bad.Code)
	}
	if empty := do(h, "POST", "/v1/exclusions", "t1", `{"field":"package","pattern":""}`); empty.Code != 400 {
		t.Errorf("empty pattern should be 400, got %d", empty.Code)
	}

	// Delete restores the issue.
	if del := do(h, "POST", "/v1/exclusions/delete", "t1", `{"id":"`+created.ID+`"}`); del.Code != 200 {
		t.Fatalf("delete: %d %s", del.Code, del.Body.String())
	}
	if b := do(h, "GET", "/v1/issues", "t1", "").Body.String(); !strings.Contains(b, "lodash") {
		t.Errorf("after delete the issue should reappear: %s", b)
	}

	// Tenant isolation: t2 sees no exclusions.
	if l := do(h, "GET", "/v1/exclusions", "t2", "").Body.String(); strings.Contains(l, "lodash") {
		t.Error("tenant isolation breached on /v1/exclusions")
	}
}

func TestRuntimeEvents_IngestAndCorrelate(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	// A web finding on /search.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Tool: "nuclei", RuleID: "nuclei::sqli",
		Severity: types.SeverityHigh, Title: "SQLi", Endpoint: "https://app.acme.com/search?q="})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		NewID: func() string { return "x" }})

	// Baseline: the issue is not attacked.
	if b := do(h, "GET", "/v1/issues", "t1", "").Body.String(); strings.Contains(b, `"attacked":1`) {
		t.Fatalf("baseline should have 0 attacked: %s", b)
	}

	// Ingest a runtime attack event on the same route (single object).
	ing := do(h, "POST", "/v1/runtime/events", "t1",
		`{"attack_kind":"sql_injection","endpoint":"/search","blocked":true,"source":"zen"}`)
	if ing.Code != 200 || !strings.Contains(ing.Body.String(), `"stored":1`) {
		t.Fatalf("ingest: %d %s", ing.Code, ing.Body.String())
	}

	// A batch ingest also works.
	if b := do(h, "POST", "/v1/runtime/events", "t1",
		`[{"attack_kind":"sql_injection","endpoint":"/search","blocked":true},{"attack_kind":"xss","endpoint":"/other"}]`); !strings.Contains(b.Body.String(), `"stored":2`) {
		t.Errorf("batch ingest should store 2: %s", b.Body.String())
	}

	// Now the /search issue is flagged attacked-in-the-wild.
	body := do(h, "GET", "/v1/issues", "t1", "").Body.String()
	if !strings.Contains(body, `"attacked":1`) {
		t.Errorf("the /search issue should be attacked: %s", body)
	}
	if !strings.Contains(body, `"attack_count":2`) {
		t.Errorf("two events hit /search, expected attack_count 2: %s", body)
	}

	// The events list reflects them (3 total, 2 blocked).
	ev := do(h, "GET", "/v1/runtime/events", "t1", "").Body.String()
	if !strings.Contains(ev, `"count":3`) || !strings.Contains(ev, `"blocked":2`) {
		t.Errorf("events list wrong: %s", ev)
	}

	// Tenant isolation: t2 sees no events, and a body-supplied tenant is ignored.
	_ = do(h, "POST", "/v1/runtime/events", "t2", `{"tenant_id":"t1","endpoint":"/x"}`)
	if e1 := do(h, "GET", "/v1/runtime/events", "t1", "").Body.String(); !strings.Contains(e1, `"count":3`) {
		t.Errorf("a body-supplied tenant must not cross tenants: %s", e1)
	}
}
