// Package azinventory is the Azure sibling of awsinventory/gcpinventory: it maps a connected Azure
// subscription's identity + network + storage state into a cloudgraph.Inventory. Same grounded (§10) mapper
// discipline — an internet-reach edge only where a resource has a public IP AND its NSG actually opens the
// port to 0.0.0.0/0 (reusing cloudgraph.InternetReachable), public storage → an internet reach, admin
// principals → Privileged. Azure has no direct assume-role concept (cross-principal escalation is RBAC-
// derived), so trust/privesc EDGES are the honest gated half here — they come from the azureiam RBAC
// evaluator over live role assignments, not this snapshot mapper. The Azure client is isolated here; the
// live list-/get- calls (a Fetcher over the subscription) are the credential-gated half.
package azinventory

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// RawAzure mirrors the SUBSET of Azure API output the mapper reads (JSON-tagged so it's a wire format too).
type RawAzure struct {
	SubscriptionID string          `json:"subscription_id"`
	Principals     []RawAzPrincipal `json:"principals,omitempty"` // managed identities / SPs / users
	VMs            []RawAzVM        `json:"vms,omitempty"`
	Storage        []RawAzStorage   `json:"storage,omitempty"`
}

// RawAzPrincipal is a managed identity / service principal / user; Admin = an Owner/Contributor or a
// privileged built-in role (fetcher-resolved from role assignments).
type RawAzPrincipal struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Admin bool   `json:"admin,omitempty"`
}

// RawAzVM is a virtual machine; PublicIP + the effective NSG ingress drive the grounded reachability eval.
type RawAzVM struct {
	ID           string `json:"id"`
	Region       string `json:"region,omitempty"`
	PublicIP     bool   `json:"public_ip,omitempty"`
	IngressJSON  string `json:"ingress,omitempty"` // effective NSG ingress ([]cloudgraph.SGRule JSON)
	ServicePort  int    `json:"service_port,omitempty"`
	ServiceProto string `json:"service_proto,omitempty"`
}

// RawAzStorage is a storage account; Public = AllowBlobPublicAccess / anonymous container (fetcher-resolved).
type RawAzStorage struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Region    string `json:"region,omitempty"`
	Public    bool   `json:"public,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

// Build maps the raw Azure subset into a cloudgraph.Inventory. Pure + grounded (§10). No trust edges: Azure
// cross-principal escalation is RBAC-derived (azureiam), the gated half — this asserts only resources,
// internet reachability, public storage, and privileged principals, all directly proven by the snapshot.
func Build(raw RawAzure) cloudgraph.Inventory {
	inv := cloudgraph.Inventory{AccountID: raw.SubscriptionID, Provider: "azure"}

	for _, p := range raw.Principals {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: p.ID, Kind: cloudgraph.KindPrincipal, Type: "azure_principal", Name: p.Name, Privileged: p.Admin,
		})
	}
	for _, vm := range raw.VMs {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: vm.ID, Kind: cloudgraph.KindResource, Type: "azure_vm", Region: vm.Region, Public: vm.PublicIP,
		})
		if !vm.PublicIP || vm.ServicePort == 0 {
			continue // grounded: no public IP / unknown port → never assert internet reachability
		}
		rules, err := cloudgraph.ParseSGRules(vm.IngressJSON)
		if err != nil {
			continue
		}
		proto := vm.ServiceProto
		if proto == "" {
			proto = "tcp"
		}
		if cloudgraph.InternetReachable(rules, vm.ServicePort, proto) {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: vm.ID})
		}
	}
	for _, s := range raw.Storage {
		kind := cloudgraph.KindResource
		sens := cloudgraph.SensNone
		if s.Sensitive {
			kind = cloudgraph.KindData
			sens = cloudgraph.SensHigh
		}
		id := s.ID
		if id == "" {
			id = "azure://storage/" + s.Name
		}
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: id, Kind: kind, Type: "azure_storage", Name: s.Name, Region: s.Region, Public: s.Public, Sensitive: sens,
		})
		if s.Public {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: id})
		}
	}
	return inv
}

// Fetcher pulls the raw Azure state for one subscription (credential-gated live half); tests inject a fake.
type Fetcher interface {
	Fetch(ctx context.Context) (RawAzure, error)
}

// Collect runs the fetcher and maps the result into the engine's Inventory.
func Collect(ctx context.Context, f Fetcher) (cloudgraph.Inventory, error) {
	if f == nil {
		return cloudgraph.Inventory{}, fmt.Errorf("azinventory: no fetcher configured")
	}
	raw, err := f.Fetch(ctx)
	if err != nil {
		return cloudgraph.Inventory{}, fmt.Errorf("azinventory: fetch: %w", err)
	}
	return Build(raw), nil
}
