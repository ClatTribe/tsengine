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
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/azureiam"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// RawAzure mirrors the SUBSET of Azure API output the mapper reads (JSON-tagged so it's a wire format too).
type RawAzure struct {
	SubscriptionID string           `json:"subscription_id"`
	Principals     []RawAzPrincipal `json:"principals,omitempty"` // managed identities / SPs / users
	VMs            []RawAzVM        `json:"vms,omitempty"`
	Storage        []RawAzStorage   `json:"storage,omitempty"`

	// RBAC — the ARM authorization plane. Without these the shape carried NO permission data at all,
	// so azureiam had no data source and Azure privesc was structurally zero for every snapshot ever
	// posted: §10 claims escalation is discovered symmetrically across AWS+GCP+Azure, which was true
	// of the EVALUATORS and false of the collectors.
	RoleAssignments []RawAzAssignment `json:"role_assignments,omitempty"`
	// RoleDefinitions supplies CUSTOM roles by name. Built-in Owner/Contributor/Reader are understood
	// inline by azureiam, so a snapshot using only those needs none.
	RoleDefinitions map[string]RawAzRoleDef `json:"role_definitions,omitempty"`
	DenyAssignments []RawAzDenyAssignment   `json:"deny_assignments,omitempty"`
}

// RawAzAssignment is a role assigned to principals at a scope. Scope is informational here: the
// snapshot is subscription-shaped, so everything in it is evaluated at one scope rather than walked
// up a hierarchy we were not given.
type RawAzAssignment struct {
	Scope      string   `json:"scope,omitempty"`
	Role       string   `json:"role"`
	Principals []string `json:"principals,omitempty"`
	Condition  string   `json:"condition,omitempty"` // ABAC — non-empty means condition-gated
}

// RawAzRoleDef is a custom role definition: actions granted minus the exclusions.
type RawAzRoleDef struct {
	Actions    []string `json:"actions,omitempty"`
	NotActions []string `json:"not_actions,omitempty"`
}

// RawAzDenyAssignment overrides allows.
type RawAzDenyAssignment struct {
	Actions           []string `json:"actions,omitempty"`
	NotActions        []string `json:"not_actions,omitempty"`
	Principals        []string `json:"principals,omitempty"`
	ExcludePrincipals []string `json:"exclude_principals,omitempty"`
	Condition         string   `json:"condition,omitempty"`
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
	derivePrivesc(&inv, raw)
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

// derivePrivesc turns the subscription's real role assignments into privilege-escalation edges — the
// Azure twin of gcpinventory.derivePrivesc and awsinventory.addPrivesc, and it closes the same hole
// they were built for: `Admin` records who ALREADY is an administrator and cannot answer who can
// BECOME one.
//
// Azure was the last of the three and the worst off. §10 says privesc-edge generation is symmetric
// across AWS+GCP+Azure, and it was — of the EVALUATORS. `azureiam.DetectPrivesc` and
// `cloudgraph.AddAzurePrivescEdges` both existed and were both tested; the ingest shape simply had no
// field for a role assignment, so nothing could ever call them with real data. Every Azure snapshot
// ever posted produced exactly zero escalation edges, by construction rather than by evidence.
//
// THE FIRM-ALLOW RULE, inherited verbatim from GCP because azureiam makes the same conservative
// choice for the same reason: an unknown custom role is treated as POSSIBLY granting anything, which
// is right for PRUNING an edge you cannot disprove and wrong for CREATING one. Under it a single
// unresolved custom role would make every principal holding it satisfy every technique. So:
//
//   - permits() accepts a firm allow, and also a grant that is real but CONDITION-GATED — we know
//     exactly which permission and only *when* is open, which is a path to report with a caveat
//     rather than one to hide. Vanishing is the one outcome §10 does not allow.
//   - firm() accepts only the unconditional case, and decides whether the edge is definite.
//
// The cost is stated rather than hidden: an escalation through a custom role whose definition was
// not supplied is NOT reported, and UnknownRoles names those roles so a caller can say which part of
// the subscription went unanswered.
func derivePrivesc(inv *cloudgraph.Inventory, raw RawAzure) {
	if len(raw.RoleAssignments) == 0 {
		return // no RBAC read: nothing evaluated, and nothing claimed
	}

	scope := &azureiam.Scope{Name: raw.SubscriptionID}
	for _, a := range raw.RoleAssignments {
		scope.Assignments = append(scope.Assignments, azureiam.Assignment{
			Role: a.Role, Principals: a.Principals, Condition: a.Condition,
		})
	}
	roles := make(map[string]azureiam.RoleDef, len(raw.RoleDefinitions))
	for name, d := range raw.RoleDefinitions {
		roles[name] = azureiam.RoleDef{Actions: d.Actions, NotActions: d.NotActions}
	}
	denies := make([]azureiam.DenyAssignment, 0, len(raw.DenyAssignments))
	for _, d := range raw.DenyAssignments {
		denies = append(denies, azureiam.DenyAssignment{
			Actions: d.Actions, NotActions: d.NotActions, Principals: d.Principals,
			ExcludePrincipals: d.ExcludePrincipals, Condition: d.Condition,
		})
	}
	ps := azureiam.PolicySet{Scope: scope, Roles: roles, Denies: denies}

	// Every principal named anywhere in the assignments, in deterministic order.
	seen := map[string]bool{}
	var principals []string
	for _, a := range raw.RoleAssignments {
		for _, p := range a.Principals {
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			principals = append(principals, p)
		}
	}
	sort.Strings(principals)

	var any bool
	for _, principal := range principals {
		permits := func(action string) bool {
			allowed, _ := azureiam.Permits(azureiam.Request{Principal: principal, Action: action}, ps)
			return allowed
		}
		firm := func(action string) bool {
			allowed, conditional := azureiam.Permits(azureiam.Request{Principal: principal, Action: action}, ps)
			return allowed && !conditional
		}
		techs := azureiam.DetectPrivesc(permits)
		if len(techs) == 0 {
			continue
		}
		// Definite only when a technique is reachable UNCONDITIONALLY. The wording is the shared
		// constant's, so all three clouds make the same claim about the same evidence rather than
		// three slightly different ones.
		condition := ""
		if len(azureiam.DetectPrivesc(firm)) == 0 {
			condition = "iam-condition-gated escalation (config-possible; validate live)"
		}
		names := make([]string, 0, len(techs))
		for _, t := range techs {
			names = append(names, t.Name)
		}
		inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{
			Principal: principal, Target: cloudgraph.AdminID,
			Detail: strings.Join(names, ", "), Condition: condition,
		})
		any = true
	}
	if any {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: cloudgraph.AdminID, Kind: cloudgraph.KindPrincipal, Type: "effective_admin",
			Name: "effective-admin", Privileged: true,
		})
	}
}

// UnknownRoles returns the roles appearing in the assignments whose definitions were not supplied,
// so a caller can state which part of the subscription it could not answer for. Azure's built-ins are
// understood inline by azureiam, so they never appear here. Empty means every role was resolvable —
// NOT that the subscription is safe.
func UnknownRoles(raw RawAzure) []string {
	seen, out := map[string]bool{}, []string{}
	for _, a := range raw.RoleAssignments {
		role := strings.TrimSpace(a.Role)
		if role == "" || seen[role] {
			continue
		}
		switch strings.ToLower(role) {
		case "owner", "contributor", "reader", "user access administrator":
			continue // azureiam understands the built-ins inline
		}
		if _, ok := raw.RoleDefinitions[role]; ok {
			continue
		}
		seen[role] = true
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}
