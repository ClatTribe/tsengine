package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func cloudRemediationHandler(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-aws", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-gh", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-other", TenantID: "t2", Kind: platform.ConnAWS, Status: platform.ConnActive})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	return h, st
}

func connConfig(t *testing.T, st store.Store, tenant, id string) map[string]string {
	t.Helper()
	conns, _ := st.ListConnections(context.Background(), tenant)
	for _, c := range conns {
		if c.ID == id {
			return c.Config
		}
	}
	return nil
}

func TestCloudRemediation_AWSEnableStoresRole(t *testing.T) {
	h, st := cloudRemediationHandler(t)
	body := `{"enabled":true,"role_arn":"arn:aws:iam::123:role/tsengine-remediate","region":"us-east-1"}`
	rec := do(h, "POST", "/v1/connections/c-aws/cloud-remediation", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	cfg := connConfig(t, st, "t1", "c-aws")
	if cfg[platform.CfgRemediationEnabled] != "true" ||
		cfg[platform.CfgRemediationRole] != "arn:aws:iam::123:role/tsengine-remediate" ||
		cfg[platform.CfgRemediationRegion] != "us-east-1" {
		t.Errorf("config not stored correctly: %+v", cfg)
	}
	// the response must never echo the sealed secret ref
	var out platform.Connection
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.SecretRef != "" {
		t.Error("response must redact SecretRef")
	}
}

func TestCloudRemediation_AWSEnableRequiresRole(t *testing.T) {
	h, _ := cloudRemediationHandler(t)
	rec := do(h, "POST", "/v1/connections/c-aws/cloud-remediation", "t1", `{"enabled":true}`)
	if rec.Code != 400 {
		t.Errorf("enabling AWS without role_arn must be 400, got %d", rec.Code)
	}
}

func TestCloudRemediation_RejectsNonCloudConnection(t *testing.T) {
	h, _ := cloudRemediationHandler(t)
	rec := do(h, "POST", "/v1/connections/c-gh/cloud-remediation", "t1", `{"enabled":false}`)
	if rec.Code != 400 {
		t.Errorf("a non-cloud connection must be 400, got %d", rec.Code)
	}
}

func TestCloudRemediation_TenantIsolation(t *testing.T) {
	h, _ := cloudRemediationHandler(t)
	// t1 must NOT be able to configure t2's connection
	rec := do(h, "POST", "/v1/connections/c-other/cloud-remediation", "t1",
		`{"enabled":true,"role_arn":"arn:aws:iam::999:role/x"}`)
	if rec.Code != 404 {
		t.Errorf("configuring another tenant's connection must be 404, got %d", rec.Code)
	}
}

func TestCloudRemediation_DisableClearsEnabled(t *testing.T) {
	h, st := cloudRemediationHandler(t)
	do(h, "POST", "/v1/connections/c-aws/cloud-remediation", "t1",
		`{"enabled":true,"role_arn":"arn:aws:iam::123:role/r"}`)
	rec := do(h, "POST", "/v1/connections/c-aws/cloud-remediation", "t1", `{"enabled":false}`)
	if rec.Code != 200 {
		t.Fatalf("disable want 200, got %d", rec.Code)
	}
	if connConfig(t, st, "t1", "c-aws")[platform.CfgRemediationEnabled] != "false" {
		t.Error("disable should set remediation_enabled=false")
	}
}
