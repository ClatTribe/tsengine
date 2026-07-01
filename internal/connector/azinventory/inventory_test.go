package azinventory

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

// REACHABILITY PRECISION: internet reach only when public IP AND the NSG actually opens the port.
func TestBuild_InternetReachOnlyWhenNSGOpen(t *testing.T) {
	open := `[{"proto":"tcp","cidr":"0.0.0.0/0","port_from":3389,"port_to":3389}]`
	corp := `[{"proto":"tcp","cidr":"10.0.0.0/8","port_from":3389,"port_to":3389}]`

	if got := internetReaches(Build(RawAzure{VMs: []RawAzVM{{ID: "vm-a", PublicIP: true, IngressJSON: open, ServicePort: 3389}}})); got != 1 {
		t.Fatalf("public IP + open NSG → 1 reach, got %d", got)
	}
	if got := internetReaches(Build(RawAzure{VMs: []RawAzVM{{ID: "vm-b", PublicIP: true, IngressJSON: corp, ServicePort: 3389}}})); got != 0 {
		t.Fatalf("corp-CIDR NSG must not be internet-open, got %d", got)
	}
	if got := internetReaches(Build(RawAzure{VMs: []RawAzVM{{ID: "vm-c", PublicIP: false, IngressJSON: open, ServicePort: 3389}}})); got != 0 {
		t.Fatalf("no public IP → no reach, got %d", got)
	}
}

func TestBuild_StoragePrincipalsClean(t *testing.T) {
	inv := Build(RawAzure{
		Principals: []RawAzPrincipal{{ID: "sp-1", Name: "deployer", Admin: true}},
		Storage:    []RawAzStorage{{Name: "public", Public: true}, {Name: "pii", Sensitive: true}},
	})
	if internetReaches(inv) != 1 {
		t.Fatalf("one public storage account → 1 reach, got %d", internetReaches(inv))
	}
	var sawAdmin, sawData bool
	for _, r := range inv.Resources {
		if r.ID == "sp-1" && r.Privileged {
			sawAdmin = true
		}
		if r.Name == "pii" && r.Kind == cloudgraph.KindData && r.Sensitive == cloudgraph.SensHigh {
			sawData = true
		}
	}
	if !sawAdmin {
		t.Error("admin principal should be Privileged")
	}
	if !sawData {
		t.Error("sensitive storage should be KindData/SensHigh")
	}
	// Azure emits no trust edges (RBAC is the gated half) — a clean subscription has none.
	if got := internetReaches(Build(RawAzure{Storage: []RawAzStorage{{Name: "priv"}}})); got != 0 {
		t.Errorf("clean subscription → 0 internet edges, got %d", got)
	}
}
