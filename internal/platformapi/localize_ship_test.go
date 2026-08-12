package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// T2 scored 1.00 on its benchmark with no customer-reachable call site — nobody had ever received a
// localization. These pin that it is now reachable AND that it degrades honestly.

func TestT2_LocalizeIsInTheAgentCatalogue(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	for _, tool := range d.EngineerCatalog(tid) {
		if tool.Schema.Name == "locate_vulnerability" {
			return
		}
	}
	t.Fatal("locate_vulnerability is not in the catalogue — T2 still ships nowhere")
}

// Without source there is nothing to rank. It must say so, and must not be mistaken for "the finding
// is not in the code".
func TestT2_NoRepoSaysSoWithoutJudgingTheFinding(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	got, err := (vulnLocalizer{d: d, tenantID: tid}).Locate(context.Background(), "f-sqli")
	if err != nil {
		t.Fatalf("localize errored instead of degrading: %v", err)
	}
	if !strings.Contains(got, "needs source access") {
		t.Errorf("want an explicit source-access message, got %q", got)
	}
	if !strings.Contains(got, "not a statement about the finding") {
		t.Error("a missing repo must not read as a verdict on the finding")
	}
}

// A finding that does not exist must fail loudly rather than localize onto some arbitrary file.
func TestT2_RefusesAnInventedFinding(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	if _, err := (vulnLocalizer{d: d, tenantID: tid}).Locate(context.Background(), "nope"); err == nil {
		t.Fatal("localized a finding that does not exist")
	}
}

// Tenant isolation: bound at construction, never from a tool argument.
func TestT2_CannotLocateAnotherTenantsFinding(t *testing.T) {
	ctx := context.Background()
	d, _ := seedEngineerTenant(t)
	if err := d.Store.PutTenant(ctx, platform.Tenant{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (vulnLocalizer{d: d, tenantID: "other"}).Locate(ctx, "f-sqli"); err == nil {
		t.Fatal("localized across a tenant boundary")
	}
}
