package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// fakeConn is a connector that discovers two repos and emits a push trigger.
type fakeConn struct{}

func (fakeConn) Kind() string                           { return platform.ConnGitHub }
func (fakeConn) OAuthURL(state, redirect string) string { return "" }
func (fakeConn) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (fakeConn) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{
		{TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository", Target: "https://github.com/acme/web"},
		{TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository", Target: "https://github.com/acme/api"},
	}, nil
}
func (fakeConn) Watch(context.Context, platform.Connection, []byte) ([]connector.Trigger, error) {
	return nil, nil
}
func (fakeConn) Apply(context.Context, platform.Connection, string, platform.Action) error {
	return nil
}

type fakeTokens struct{}

func (fakeTokens) Resolve(context.Context, platform.Connection) (string, error) { return "tok", nil }

// fakeScanner returns one finding per asset, tagged with the asset target.
type fakeScanner struct{ calls int }

func (s *fakeScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	s.calls++
	return []types.Finding{{ID: "f-" + a.Target, Severity: types.SeverityHigh, Title: "issue in " + a.Target}}, nil
}

func newService() (*Service, *fakeScanner, store.Store) {
	st := store.NewMemory()
	sc := &fakeScanner{}
	n := 0
	return &Service{
		Store:      st,
		Connectors: connector.NewRegistry(fakeConn{}),
		Tokens:     fakeTokens{},
		Scanner:    sc,
		NewID:      func() string { n++; return itoa(n) },
	}, sc, st
}

// OM-5 / WRD-4 fail-closed: an asset whose connection is quarantined (or otherwise not
// active) is NOT scanned, while an active connection's asset still is.
func TestQuarantinedConnectionNotScanned(t *testing.T) {
	svc, sc, st := newService()
	ctx := context.Background()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-active", TenantID: "t1", Kind: "github", Status: platform.ConnActive})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-quar", TenantID: "t1", Kind: "github", Status: platform.ConnQuarantined})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", ConnectionID: "c-active", Type: "repository", Target: "ok"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-quar", TenantID: "t1", ConnectionID: "c-quar", Type: "repository", Target: "quar"})

	n, err := svc.RescanTenant(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || sc.calls != 1 {
		t.Fatalf("only the active connection's asset should scan: scanned=%d calls=%d", n, sc.calls)
	}
}

// The kill-switch (Tenant.AgentsHalted) pauses scanning: a halted tenant gets no new
// engagements until it is disengaged.
func TestKillSwitchPausesScanning(t *testing.T) {
	svc, sc, st := newService()
	ctx := context.Background()
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "repository", Target: "x"})

	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme", AgentsHalted: true})
	n, err := svc.RescanTenant(ctx, "t1")
	if err != nil || n != 0 || sc.calls != 0 {
		t.Fatalf("halted tenant must not scan: n=%d calls=%d err=%v", n, sc.calls, err)
	}

	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"}) // disengage
	if n, _ = svc.RescanTenant(ctx, "t1"); n != 1 {
		t.Fatalf("after disengage want 1 scanned, got %d", n)
	}
}

func TestDiscoverAndScan_PersistsFindingsTenantScoped(t *testing.T) {
	svc, sc, st := newService()
	ctx := context.Background()
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}

	n, err := svc.DiscoverAndScan(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || sc.calls != 2 {
		t.Fatalf("want 2 assets scanned, got n=%d calls=%d", n, sc.calls)
	}

	// both assets registered + both findings persisted under t1
	assets, _ := st.ListAssets(ctx, "t1")
	if len(assets) != 2 {
		t.Errorf("want 2 assets stored, got %d", len(assets))
	}
	fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	// an engagement was recorded per scan
	engs, _ := st.ListEngagements(ctx, "t1")
	if len(engs) != 2 {
		t.Errorf("want 2 engagements, got %d", len(engs))
	}

	// isolation: another tenant sees nothing
	other, _ := st.ListFindings(ctx, "t2", store.FindingFilter{})
	if len(other) != 0 {
		t.Errorf("ISOLATION: t2 must see no findings, got %d", len(other))
	}
}

func TestOnTrigger_RescansMatchingAsset(t *testing.T) {
	svc, sc, st := newService()
	ctx := context.Background()
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}
	_, _ = svc.DiscoverAndScan(ctx, conn) // seed assets (2 scans)
	before := sc.calls

	eng, err := svc.OnTrigger(ctx, connector.Trigger{
		TenantID: "t1", ConnectionID: "c1",
		AssetTarget: "https://github.com/acme/web", Kind: platform.TriggerPush,
	})
	if err != nil {
		t.Fatal(err)
	}
	if eng.Trigger != platform.TriggerPush {
		t.Errorf("engagement trigger = %q", eng.Trigger)
	}
	if sc.calls != before+1 {
		t.Errorf("trigger should rescan exactly the matching asset (1 more scan), got %d→%d", before, sc.calls)
	}
	_ = st

	// a trigger for an unknown target errors (no silent miss)
	if _, err := svc.OnTrigger(ctx, connector.Trigger{TenantID: "t1", AssetTarget: "https://github.com/acme/ghost"}); err == nil {
		t.Error("unknown trigger target should error")
	}
}

// itoa avoids strconv import noise in the deterministic id gen.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
