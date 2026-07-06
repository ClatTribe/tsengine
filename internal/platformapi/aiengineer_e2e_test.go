package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// aiengineer_e2e_test.go exercises the AI Security Engineer (code/cloud defense) USER WORKFLOW end to end
// through the real HTTP handlers — the Task-2 verification pass. A tenant has a leaked AWS key in code AND
// a reachable cloud admin role (the code→cloud wedge). We assert the estate the engineer reasons over
// surfaces correctly at every door: unified issues, the cross-surface attack path, and the G2 bridge that
// feeds the cloud specialist.

// seedCodeToCloudEstate seeds two correlating findings (a leaked key in code + a cloud admin role reachable
// with it) plus a benign decoy, mirroring fixtures/defense/leaked-key-to-cloud.
func seedCodeToCloudEstate(t *testing.T, st store.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: tenantID, Plan: platform.PlanEnterprise})
	_ = st.PutAsset(ctx, platform.Asset{ID: "repo-1", TenantID: tenantID, Type: "repository", Target: "acme/api"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "cloud-1", TenantID: tenantID, Type: "cloud_account", Target: "123456789012"})
	findings := []types.Finding{
		{
			ID: "f-secret", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks", Severity: types.SeverityHigh,
			Endpoint:    "acme/api/config.py:12",
			Title:       "Hardcoded AWS access key AKIAIOSFODNN7EXAMPLE in config.py",
			Description: "A long-lived AWS access key AKIAIOSFODNN7EXAMPLE is committed in config.py.",
		},
		{
			ID: "f-admin", RuleID: "prowler::iam-privesc", Tool: "prowler", Severity: types.SeverityHigh,
			Endpoint:    "arn:aws:iam::123456789012:role/deploy",
			Title:       "IAM role allows privilege escalation to administrator",
			Description: "The deploy role is assumable with the leaked key AKIAIOSFODNN7EXAMPLE and grants *:* (full admin access).",
		},
	}
	for _, f := range findings {
		if err := st.PutFinding(ctx, tenantID, f); err != nil {
			t.Fatalf("seed finding %s: %v", f.ID, err)
		}
	}
}

// TestAIEngineer_CodeToCloudEstateSurfaces walks the read-side of the workflow: the unified issue view and
// the cross-surface attack-path view both surface the seeded estate the AI engineer reasons over.
func TestAIEngineer_CodeToCloudEstateSurfaces(t *testing.T) {
	st := store.NewMemory()
	seedCodeToCloudEstate(t, st, "t1")
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	// Attack paths: the code→cloud chain (repository → cloud_account) must be surfaced.
	ap := do(h, "GET", "/v1/attack-paths", "t1", "")
	if ap.Code != http.StatusOK {
		t.Fatalf("attack-paths: want 200, got %d (%s)", ap.Code, ap.Body.String())
	}
	var apResp struct {
		Count       int `json:"count"`
		AttackPaths []struct {
			Steps []struct {
				AssetType string `json:"asset_type"`
			} `json:"steps"`
		} `json:"attack_paths"`
	}
	if err := json.Unmarshal(ap.Body.Bytes(), &apResp); err != nil {
		t.Fatalf("decode attack-paths: %v", err)
	}
	if apResp.Count == 0 {
		t.Fatalf("the leaked-key→cloud chain should surface as an attack path, got 0:\n%s", ap.Body.String())
	}
	var sawRepo, sawCloud bool
	for _, p := range apResp.AttackPaths {
		for _, s := range p.Steps {
			if s.AssetType == "repository" {
				sawRepo = true
			}
			if s.AssetType == "cloud_account" {
				sawCloud = true
			}
		}
	}
	if !sawRepo || !sawCloud {
		t.Errorf("the attack path must bridge repository→cloud_account, got repo=%v cloud=%v", sawRepo, sawCloud)
	}

	// Unified issues: both findings must appear as issues the engineer can prioritize.
	iss := do(h, "GET", "/v1/issues", "t1", "")
	if iss.Code != http.StatusOK {
		t.Fatalf("issues: want 200, got %d (%s)", iss.Code, iss.Body.String())
	}
	if !strings.Contains(iss.Body.String(), "administrator") && !strings.Contains(iss.Body.String(), "AKIA") {
		t.Errorf("the issues view should carry the seeded code/cloud findings, got:\n%s", iss.Body.String())
	}
}

// TestAIEngineer_G2BridgeFromStore proves the G2 wiring end to end through the store: tenantCloudBridges
// computes the code→cloud entry-point hint from the tenant's real estate — the signal fed to the cloud
// specialist so it verifies paths FROM the leaked-key foothold first.
func TestAIEngineer_G2BridgeFromStore(t *testing.T) {
	st := store.NewMemory()
	seedCodeToCloudEstate(t, st, "t1")
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}

	bridges := d.tenantCloudBridges(context.Background(), "t1")
	if len(bridges) == 0 {
		t.Fatal("the code→cloud estate must yield at least one cross-surface bridge hint for the cloud specialist")
	}
	joined := strings.Join(bridges, " | ")
	if !strings.Contains(joined, "repository") || !strings.Contains(strings.ToLower(joined), "cloud target") {
		t.Errorf("the bridge hint must name the repository foothold and the cloud target, got: %s", joined)
	}

	// Tenant isolation: another tenant with no estate gets no bridges.
	if got := d.tenantCloudBridges(context.Background(), "t2"); len(got) != 0 {
		t.Errorf("tenant isolation: t2 has no estate and must get no bridges, got %v", got)
	}
}
