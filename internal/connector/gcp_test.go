package connector

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestGCP_KindAndOAuthURL(t *testing.T) {
	g := NewGCP("tsengine-scanner@tsengine.iam.gserviceaccount.com")
	if g.Kind() != platform.ConnGCP {
		t.Errorf("kind = %q", g.Kind())
	}
	u := g.OAuthURL("tenant-123", "")
	for _, want := range []string{"iam-admin/iam", "state=tenant-123", "securityReviewer", "tsengine-scanner"} {
		if !strings.Contains(u, want) {
			t.Errorf("oauth url missing %q: %s", want, u)
		}
	}
}

func TestGCP_ExchangeRecordsProject(t *testing.T) {
	g := NewGCP("sa@x")
	conn, err := g.Exchange(context.Background(), "  acme-prod-123  ", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if conn.Kind != platform.ConnGCP || conn.Account != "acme-prod-123" || conn.SecretRef != "acme-prod-123" || conn.Status != platform.ConnActive {
		t.Errorf("connection wrong: %+v", conn)
	}
}

func TestGCP_ExchangeRejectsBadProjectID(t *testing.T) {
	g := NewGCP("sa@x")
	for _, bad := range []string{"short", "UPPER-case", "1starts-with-digit", "ends-with-hyphen-", "has_underscore", strings.Repeat("a", 31)} {
		if _, err := g.Exchange(context.Background(), bad, ""); err == nil {
			t.Errorf("project id %q should be rejected", bad)
		}
	}
	// a valid one passes
	if _, err := g.Exchange(context.Background(), "my-project-1", ""); err != nil {
		t.Errorf("valid project id rejected: %v", err)
	}
}

func TestGCP_DiscoverYieldsCloudAccount(t *testing.T) {
	g := NewGCP("sa@x")
	assets, err := g.Discover(context.Background(), platform.Connection{ID: "c1", TenantID: "t1", Account: "acme-prod-123"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("want 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "cloud_account" || a.Target != "acme-prod-123" || a.ConnectionID != "c1" {
		t.Errorf("asset wrong: %+v", a)
	}
	if a.Meta["provider"] != "gcp" || a.Meta["project_id"] != "acme-prod-123" {
		t.Errorf("asset meta wrong: %+v", a.Meta)
	}
}

func TestGCP_WatchNoop(t *testing.T) {
	g := NewGCP("sa@x")
	if trigs, _ := g.Watch(context.Background(), platform.Connection{}, []byte(`{}`)); len(trigs) != 0 {
		t.Errorf("cloud Watch should be a no-op, got %+v", trigs)
	}
}

func TestGCP_ApplyIsHonestStub(t *testing.T) {
	g := NewGCP("sa@x")
	// no remediation_type → honest error, never a false "done"
	if err := g.Apply(context.Background(), platform.Connection{}, "", platform.Action{ID: "a1"}); err == nil {
		t.Error("Apply with no remediation_type must error")
	}
	// a known type still has no live write path → honest error
	err := g.Apply(context.Background(), platform.Connection{}, "", platform.Action{ID: "a2", Payload: map[string]any{"remediation_type": "bucket_lock"}})
	if err == nil || !strings.Contains(err.Error(), "no live GCP write path") {
		t.Errorf("Apply should surface the no-live-write-path stub, got %v", err)
	}
}
