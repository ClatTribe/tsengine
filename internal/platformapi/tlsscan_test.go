package platformapi

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestTLSScan_NoHostNoAssets(t *testing.T) {
	d := Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"}
	rec := do(NewHandler(d), "POST", "/v1/tls/scan", "t1", `{}`)
	if rec.Code != 200 {
		t.Fatalf("empty host + no assets → 200 with a note, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTLSResolveAllowed_ScreensPrivate(t *testing.T) {
	if _, ok := tlsResolveAllowed(context.Background(), "127.0.0.1"); ok {
		t.Error("loopback must be screened out (SSRF)")
	}
	if _, ok := tlsResolveAllowed(context.Background(), "10.0.0.5:443"); ok {
		t.Error("private IP must be screened out (SSRF)")
	}
	// a public IP literal is allowed AND returned for pinning (no re-resolution).
	if ip, ok := tlsResolveAllowed(context.Background(), "8.8.8.8"); !ok || ip == nil || ip.String() != "8.8.8.8" {
		t.Errorf("public IP must be allowed and returned for pinning, got ip=%v ok=%v", ip, ok)
	}
}

// ── EVERY STORED FINDING NEEDS ITS OWN ID ────────────────────────────────────────────────────────

// internal/tlsscan is a pure assessor and does not assign finding ids; every sibling ingest handler
// assigns them before storing. This one did not, so every TLS finding was stored under the same empty
// key and silently overwrote the previous one.
//
// Observed against a live platform: scanning expired.badssl.com and then badssl.com left ONE finding
// in the store, the second having replaced the first. A ten-host scan keeps one finding and the
// customer reads the other nine hosts as clean — and the failure is invisible, because the RESPONSE
// still lists every finding it just found. Only the store is short.
//
// Hosts are given as public IP literals so tlsResolveAllowed parses them directly: no DNS, and the
// SSRF screen (which correctly refuses private addresses) is satisfied without a network.
func TestTLSScan_StoredFindingsGetDistinctIDs(t *testing.T) {
	st := store.NewMemory()
	// Two hosts × two findings, so a collision shows up both within a host and across hosts.
	assess := func(_ context.Context, host string, _ net.IP) ([]types.Finding, error) {
		return []types.Finding{
			{RuleID: "tlsscan::cert-expired", Endpoint: "https://" + host, Severity: types.SeverityHigh},
			{RuleID: "tlsscan::legacy-protocol-supported", Endpoint: "https://" + host, Severity: types.SeverityMedium},
		}, nil
	}
	// A FIXED NewID, which is how this package's tests normally inject ids. It also makes the index
	// load-bearing rather than incidental: with the default nanosecond id every call differs anyway,
	// so a per-host index would look correct while still colliding across hosts under a stable id.
	d := Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		TLSAssess: assess, NewID: func() string { return "fixed" },
	}

	// Two assets, so the default (no explicit host) path scans both. The counter that assigns ids has
	// to run ACROSS hosts — a per-host index would still collide between them.
	ctx := context.Background()
	for i, target := range []string{"https://93.184.216.34", "https://1.1.1.1"} {
		if err := st.PutAsset(ctx, platform.Asset{
			ID: "a" + strconv.Itoa(i), TenantID: "t1", Type: "web_application", Target: target,
		}); err != nil {
			t.Fatal(err)
		}
	}

	rec := do(NewHandler(d), "POST", "/v1/tls/scan", "t1", `{}`)
	if rec.Code != 200 {
		t.Fatalf("scan failed: %d %s", rec.Code, rec.Body.String())
	}

	fs, err := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("stored %d of 4 findings — they are overwriting each other: %+v", len(fs), fs)
	}
	seen := map[string]bool{}
	for _, f := range fs {
		if f.ID == "" {
			t.Errorf("a stored finding has no id: %+v", f)
		}
		if seen[f.ID] {
			t.Errorf("duplicate finding id %q — one finding is hiding another", f.ID)
		}
		seen[f.ID] = true
	}
}
