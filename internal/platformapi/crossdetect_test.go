package platformapi

import (
	"context"
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
