package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type hrisWSSource struct{ ws operate.Workspace }

func (s hrisWSSource) Workspace(context.Context, platform.Asset) (operate.Workspace, error) {
	return s.ws, nil
}

// The joiner/leaver join runs on the SCHEDULED path: with a stored roster, every workspace scan
// joins it against the accounts, so a leaver's still-enabled account is a finding on the next pass
// — and "hris" is reported as a producer that ran, so its incident can later resolve.
func TestOperateRunner_JoinsStoredRosterAgainstAccounts(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.ReplaceEmployees(ctx, "t1", "merge", []platform.Employee{
		{TenantID: "t1", Source: "merge", ID: "e1", Name: "Alice", WorkEmail: "alice@acme.io", Status: platform.EmploymentTerminated, EndDate: "2026-06-01"},
		{TenantID: "t1", Source: "merge", ID: "e2", WorkEmail: "bob@acme.io", Status: platform.EmploymentActive},
	})
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{
		{Email: "alice@acme.io", Admin: true, MFA: true},
		{Email: "bob@acme.io", MFA: true},
	}}
	r := &OperateRunner{Source: hrisWSSource{ws}, Employees: st}
	asset := platform.Asset{ID: "a1", TenantID: "t1", Type: WorkspaceType, Target: "okta:acme"}

	fs, rep, err := r.ScanWithReport(ctx, asset)
	if err != nil {
		t.Fatal(err)
	}
	var leaver *types.Finding
	for i := range fs {
		if fs[i].RuleID == "hris::leaver-with-active-account" {
			leaver = &fs[i]
		}
	}
	if leaver == nil || leaver.Endpoint != "alice@acme.io" || leaver.Severity != types.SeverityCritical {
		t.Fatalf("alice (admin, terminated, enabled) must be a critical finding alongside the operate ones: %+v", fs)
	}
	if len(rep.ToolsRan) != 1 || rep.ToolsRan[0] != "hris" {
		t.Errorf("the join ran → 'hris' is a covered producer this pass, got %v", rep.ToolsRan)
	}
	// And the plain Scan path returns the same set (it delegates).
	fs2, err := r.Scan(ctx, asset)
	if err != nil || len(fs2) != len(fs) {
		t.Errorf("Scan must equal ScanWithReport's findings: %d vs %d (%v)", len(fs2), len(fs), err)
	}
}

// No roster → no join, and CRUCIALLY "hris" is NOT reported as having run: an empty roster is not
// evidence that nobody left, and covering the producer would let a leaver's incident resolve.
func TestOperateRunner_NoRosterDoesNotCoverHRIS(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{{Email: "alice@acme.io", MFA: true}}}
	asset := platform.Asset{ID: "a1", TenantID: "t1", Type: WorkspaceType}

	withSource := &OperateRunner{Source: hrisWSSource{ws}, Employees: st}
	_, rep, err := withSource.ScanWithReport(ctx, asset)
	if err != nil || len(rep.ToolsRan) != 0 {
		t.Errorf("empty roster: no hris coverage, got %v (%v)", rep.ToolsRan, err)
	}
	// A roster with no matching addresses is also "could not conclude" — the join's own report says
	// so, and the runner must honour it rather than covering the producer.
	_ = st.ReplaceEmployees(ctx, "t1", "merge", []platform.Employee{{TenantID: "t1", Source: "merge", ID: "e1", Name: "No Email"}})
	_, rep, _ = withSource.ScanWithReport(ctx, asset)
	if len(rep.ToolsRan) != 0 {
		t.Errorf("roster without addresses: the join could not run, must not be covered: %v", rep.ToolsRan)
	}
	// Without an EmployeeSource at all, behaviour is exactly the pre-existing one.
	plain := &OperateRunner{Source: hrisWSSource{ws}}
	_, rep, _ = plain.ScanWithReport(ctx, asset)
	if len(rep.ToolsRan) != 0 {
		t.Errorf("no Employees wired: no report, got %v", rep.ToolsRan)
	}
}
