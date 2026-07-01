// Package gcpinventory is the GCP sibling of awsinventory: it maps a connected GCP project's IAM + network
// + storage state into a cloudgraph.Inventory (the attack-path engine's fuel). Same grounded (§10) mapper
// discipline — a trust (impersonation) edge only where a principal really holds serviceAccountTokenCreator
// on a service account, an internet-reach edge only where a resource has an external IP AND a firewall rule
// actually opens the port to 0.0.0.0/0 (reusing cloudgraph.InternetReachable). The GCP client is isolated
// here; the live list-/get- calls (a Fetcher over the connected project) are the credential-gated half.
package gcpinventory

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// RawGCP mirrors the SUBSET of GCP API output the mapper reads. Pure data (JSON-tagged so it's a wire
// format too — an external collector can POST it), no SDK types.
type RawGCP struct {
	ProjectID       string           `json:"project_id"`
	ServiceAccounts []RawGCPSA       `json:"service_accounts,omitempty"`
	Members         []RawGCPMember   `json:"members,omitempty"` // users/groups with project-level roles
	Instances       []RawGCPInstance `json:"instances,omitempty"`
	Buckets         []RawGCPBucket   `json:"buckets,omitempty"`
}

// RawGCPSA is a service account; Impersonators are the principals a fetcher resolved as holding
// roles/iam.serviceAccountTokenCreator on it (GCP's assume-role analog). Admin = an owner/editor/admin role.
type RawGCPSA struct {
	Email         string   `json:"email"`
	Admin         bool     `json:"admin,omitempty"`
	Impersonators []string `json:"impersonators,omitempty"`
}

// RawGCPMember is a user/group with project IAM roles (member string "user:foo@" / "group:bar@").
type RawGCPMember struct {
	Member string `json:"member"`
	Admin  bool   `json:"admin,omitempty"`
}

// RawGCPInstance is a GCE VM; ExternalIP + the effective firewall ingress drive the grounded reachability eval.
type RawGCPInstance struct {
	Name         string `json:"name"`
	Region       string `json:"region,omitempty"`
	ExternalIP   bool   `json:"external_ip,omitempty"`
	IngressJSON  string `json:"ingress,omitempty"` // effective firewall ingress ([]cloudgraph.SGRule JSON)
	ServicePort  int    `json:"service_port,omitempty"`
	ServiceProto string `json:"service_proto,omitempty"`
}

// RawGCPBucket is a GCS bucket; Public = an allUsers/allAuthenticatedUsers IAM binding (fetcher-resolved).
type RawGCPBucket struct {
	Name      string `json:"name"`
	Region    string `json:"region,omitempty"`
	Public    bool   `json:"public,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

// Build maps the raw GCP subset into a cloudgraph.Inventory. Pure + grounded (§10).
func Build(raw RawGCP) cloudgraph.Inventory {
	inv := cloudgraph.Inventory{AccountID: raw.ProjectID, Provider: "gcp"}

	for _, sa := range raw.ServiceAccounts {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: sa.Email, Kind: cloudgraph.KindPrincipal, Type: "gcp_service_account", Name: sa.Email, Privileged: sa.Admin,
		})
		for _, imp := range sa.Impersonators {
			// impersonation is GCP's assume-role: the principal can mint a token for the SA
			inv.Trusts = append(inv.Trusts, cloudgraph.InvTrust{Principal: imp, Role: sa.Email})
		}
	}
	for _, m := range raw.Members {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: m.Member, Kind: cloudgraph.KindPrincipal, Type: "gcp_member", Name: m.Member, Privileged: m.Admin,
		})
	}
	for _, in := range raw.Instances {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: in.Name, Kind: cloudgraph.KindResource, Type: "gce_instance", Region: in.Region, Public: in.ExternalIP,
		})
		if !in.ExternalIP || in.ServicePort == 0 {
			continue // grounded: no external IP / unknown port → never assert internet reachability
		}
		rules, err := cloudgraph.ParseSGRules(in.IngressJSON)
		if err != nil {
			continue
		}
		proto := in.ServiceProto
		if proto == "" {
			proto = "tcp"
		}
		if cloudgraph.InternetReachable(rules, in.ServicePort, proto) {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: in.Name})
		}
	}
	for _, b := range raw.Buckets {
		kind := cloudgraph.KindResource
		sens := cloudgraph.SensNone
		if b.Sensitive {
			kind = cloudgraph.KindData
			sens = cloudgraph.SensHigh
		}
		id := "gs://" + b.Name
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: id, Kind: kind, Type: "gcs_bucket", Name: b.Name, Region: b.Region, Public: b.Public, Sensitive: sens,
		})
		if b.Public {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: id})
		}
	}
	return inv
}

// Fetcher pulls the raw GCP state for one project (the credential-gated live half); tests inject a fake.
type Fetcher interface {
	Fetch(ctx context.Context) (RawGCP, error)
}

// Collect runs the fetcher and maps the result into the engine's Inventory.
func Collect(ctx context.Context, f Fetcher) (cloudgraph.Inventory, error) {
	if f == nil {
		return cloudgraph.Inventory{}, fmt.Errorf("gcpinventory: no fetcher configured")
	}
	raw, err := f.Fetch(ctx)
	if err != nil {
		return cloudgraph.Inventory{}, fmt.Errorf("gcpinventory: fetch: %w", err)
	}
	return Build(raw), nil
}
