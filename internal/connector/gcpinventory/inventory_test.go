package gcpinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func internetReaches(inv cloudgraph.Inventory) int {
	n := 0
	for _, r := range inv.Reaches {
		if r.From == cloudgraph.InternetID {
			n++
		}
	}
	return n
}

// SA impersonation is GCP's assume-role: an impersonator → a trust edge to the service account.
func TestBuild_ImpersonationTrustEdge(t *testing.T) {
	inv := Build(RawGCP{
		ProjectID: "proj-1",
		ServiceAccounts: []RawGCPSA{{
			Email: "deploy@proj-1.iam.gserviceaccount.com", Admin: true,
			Impersonators: []string{"user:dev@acme.com"},
		}},
	})
	if len(inv.Trusts) != 1 {
		t.Fatalf("want 1 impersonation trust edge, got %d", len(inv.Trusts))
	}
	if inv.Trusts[0].Principal != "user:dev@acme.com" {
		t.Errorf("wrong impersonator: %+v", inv.Trusts[0])
	}
	if g := cloudgraph.Ingest(inv); g.Node("deploy@proj-1.iam.gserviceaccount.com") == nil {
		t.Error("SA node missing from ingested graph")
	}
}

// REACHABILITY PRECISION: internet reach only when external IP AND the firewall actually opens the port.
func TestBuild_InternetReachOnlyWhenFirewallOpen(t *testing.T) {
	open := `[{"proto":"tcp","cidr":"0.0.0.0/0","port_from":22,"port_to":22}]`
	corp := `[{"proto":"tcp","cidr":"10.0.0.0/8","port_from":22,"port_to":22}]`

	if got := internetReaches(Build(RawGCP{Instances: []RawGCPInstance{{Name: "vm-a", ExternalIP: true, IngressJSON: open, ServicePort: 22}}})); got != 1 {
		t.Fatalf("external IP + open firewall → 1 reach, got %d", got)
	}
	if got := internetReaches(Build(RawGCP{Instances: []RawGCPInstance{{Name: "vm-b", ExternalIP: true, IngressJSON: corp, ServicePort: 22}}})); got != 0 {
		t.Fatalf("corp-CIDR firewall must not be internet-open, got %d", got)
	}
	if got := internetReaches(Build(RawGCP{Instances: []RawGCPInstance{{Name: "vm-c", ExternalIP: false, IngressJSON: open, ServicePort: 22}}})); got != 0 {
		t.Fatalf("no external IP → no reach, got %d", got)
	}
}

func TestBuild_BucketsAndClean(t *testing.T) {
	inv := Build(RawGCP{Buckets: []RawGCPBucket{{Name: "public", Public: true}, {Name: "pii", Sensitive: true}}})
	if internetReaches(inv) != 1 {
		t.Fatalf("one public bucket → 1 reach, got %d", internetReaches(inv))
	}
	var sawData bool
	for _, r := range inv.Resources {
		if r.Name == "pii" && r.Kind == cloudgraph.KindData && r.Sensitive == cloudgraph.SensHigh {
			sawData = true
		}
	}
	if !sawData {
		t.Error("sensitive bucket should be KindData/SensHigh")
	}
	if got := internetReaches(Build(RawGCP{Buckets: []RawGCPBucket{{Name: "priv"}}})); got != 0 {
		t.Errorf("clean project → 0 internet edges, got %d", got)
	}
}
