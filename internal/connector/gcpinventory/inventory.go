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

	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/gcpiam"
)

// RawGCP mirrors the SUBSET of GCP API output the mapper reads. Pure data (JSON-tagged so it's a wire
// format too — an external collector can POST it), no SDK types.
type RawGCP struct {
	ProjectID       string           `json:"project_id"`
	ServiceAccounts []RawGCPSA       `json:"service_accounts,omitempty"`
	Members         []RawGCPMember   `json:"members,omitempty"` // users/groups with project-level roles
	Instances       []RawGCPInstance `json:"instances,omitempty"`
	Buckets         []RawGCPBucket   `json:"buckets,omitempty"`
	// Bindings are the project's IAM policy bindings. They are what makes "can this
	// principal BECOME admin" answerable; the per-principal Admin flag only answers "is
	// it already", and the second is the attack path.
	Bindings []RawGCPBinding `json:"bindings,omitempty"`
	// Denies are the project's IAM DENY policies. GCP evaluates deny BEFORE allow, so a deny on
	// resourcemanager.projects.setIamPolicy blocks the escalation an allow would otherwise permit —
	// and it is the documented guardrail a customer puts in place for exactly this.
	//
	// gcpiam.Authorize has always evaluated denies. This struct could not EXPRESS one, so
	// derivePrivesc built its PolicySet without any, and a project protected by a deny policy was
	// still reported as having a privilege-escalation path to administrator. That is a false
	// positive against the customers who took the strongest available precaution.
	//
	// The same question BishopFox's AWS control set asks of every tool: "Does the tool evaluate
	// deny's first before allows? Many tools ignore or incorrectly handle DENY actions." GCP had no
	// answer because the input could not carry them.
	Denies []RawGCPDeny `json:"denies,omitempty"`
	// RoleDefs maps a role name to the permissions it grants ("*" = all). REQUIRED for
	// any custom role: gcpiam treats a role it has no definition for as POSSIBLY granting
	// anything, so without definitions every principal would appear able to escalate.
	// See derivePrivesc for why that possibility is not enough to draw an edge.
	RoleDefs map[string][]string `json:"role_defs,omitempty"`
	// WIFProviders are the project's Workload Identity Federation pool providers — the objects that
	// decide WHICH external tokens this project accepts.
	//
	// Without them internal/gcpwif had nothing to assess, so an estate federating entirely through
	// GitHub Actions or an external IdP was invisible: no finding, and (before the coverage note)
	// not even an admission that we had not looked. GCP splits the decision across two objects
	// usually edited by different people — the provider's attribute condition and the service
	// account's IAM binding — and neither half is wrong on its own, which is exactly why the join
	// has to be expressible here.
	WIFProviders []RawGCPWIFProvider `json:"wif_providers,omitempty"`
}

// RawGCPWIFProvider is one workload-identity pool provider, in the shape the GCP API returns it.
type RawGCPWIFProvider struct {
	ProjectNumber string `json:"project_number"`
	PoolID        string `json:"pool_id"`
	ID            string `json:"id"`
	// IssuerURI names WHO is trusted (e.g. https://token.actions.githubusercontent.com).
	IssuerURI        string   `json:"issuer_uri,omitempty"`
	AllowedAudiences []string `json:"allowed_audiences,omitempty"`
	// AttributeMapping maps google.*/attribute.* to assertion.* expressions.
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	// AttributeCondition is the CEL gate. EMPTY is the one thing we can state definitively — that
	// there is no condition at all; the adequacy of a present one is not ours to judge.
	AttributeCondition string `json:"attribute_condition,omitempty"`
}

// RawGCPBinding is one IAM policy binding: a role granted to members, optionally
// condition-gated.
// RawGCPDeny is one IAM deny policy rule, mirroring gcpiam.DenyRule. A rule whose condition we
// cannot resolve is treated as NOT denying, the same conservative choice cloudiam makes: refusing to
// prune a path on a deny we are not sure applies.
type RawGCPDeny struct {
	DeniedPermissions   []string `json:"denied_permissions"`
	DeniedPrincipals    []string `json:"denied_principals"`
	ExceptionPrincipals []string `json:"exception_principals,omitempty"`
	Condition           string   `json:"condition,omitempty"`
}

type RawGCPBinding struct {
	Role      string   `json:"role"`
	Members   []string `json:"members"`
	Condition string   `json:"condition,omitempty"`
}

// RawGCPSA is a service account; Impersonators are the principals a fetcher resolved as holding
// roles/iam.serviceAccountTokenCreator on it (GCP's assume-role analog). Admin = an owner/editor/admin role.
type RawGCPSA struct {
	Email         string   `json:"email"`
	Admin         bool     `json:"admin,omitempty"`
	Impersonators []string `json:"impersonators,omitempty"`
	// Bindings are the IAM policy ON THIS SERVICE ACCOUNT — who may impersonate it, and under
	// which role. Distinct from Impersonators, which is a flat list with no role: gcpwif needs the
	// role to tell an impersonation grant from an unrelated one, and assuming a role that was not
	// reported would be guessing at the very fact the finding turns on.
	Bindings []RawGCPBinding `json:"bindings,omitempty"`
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
	derivePrivesc(&inv, raw)
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

// derivePrivesc turns the project's real IAM bindings into privilege-escalation edges,
// the GCP twin of awsinventory's addPrivesc and for the same reason: no production ingest
// path produced one, so a principal that could MINT ITSELF an admin token was invisible
// while `Admin` only recorded principals that already were one.
//
// THE FIRM-ALLOW RULE, and why it is not over-caution. gcpiam deliberately treats a role
// whose definition it does not have as POSSIBLY granting the permission — the right
// default for path-pruning, because dropping an edge you cannot disprove hides a real
// route. It is the wrong default for CREATING one. Under it, every principal holding any
// custom role would satisfy every escalation technique, and the graph would fill with
// escalations inferred from nothing but a missing role definition. So an edge requires a
// FIRM allow: a role we actually have the permissions for, a member we resolved, and no
// unevaluated condition.
//
// The cost is stated rather than hidden: an escalation through a custom role we lack the
// definition for is NOT reported, and UnknownRoles names those roles so a caller can say
// which part of the project it could not answer for. Absence of evidence is not evidence
// of absence, and it is not evidence of presence either.
func derivePrivesc(inv *cloudgraph.Inventory, raw RawGCP) {
	if len(raw.Bindings) == 0 {
		return // no IAM policy read: nothing to evaluate, and nothing claimed
	}
	res := &gcpiam.Resource{Name: raw.ProjectID}
	for _, b := range raw.Bindings {
		res.Bindings = append(res.Bindings, gcpiam.Binding{
			Role: b.Role, Members: b.Members, Condition: b.Condition,
		})
	}
	denies := make([]gcpiam.DenyRule, 0, len(raw.Denies))
	for _, d := range raw.Denies {
		denies = append(denies, gcpiam.DenyRule{
			DeniedPermissions:   d.DeniedPermissions,
			DeniedPrincipals:    d.DeniedPrincipals,
			ExceptionPrincipals: d.ExceptionPrincipals,
			Condition:           d.Condition,
		})
	}
	ps := gcpiam.PolicySet{Resource: res, Roles: raw.RoleDefs, Denies: denies}

	// Every principal named anywhere in the bindings, in deterministic order.
	seen := map[string]bool{}
	var principals []string
	for _, b := range raw.Bindings {
		for _, m := range b.Members {
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			principals = append(principals, m)
		}
	}
	sort.Strings(principals)

	var any bool
	for _, member := range principals {
		// TWO predicates, as AWS does (cloudgraph.AddPrivescEdges). Detecting only with the
		// firm one — which is what this did — makes a CONDITION-GATED escalation vanish
		// entirely, and vanishing is the one outcome §10 does not allow.
		//
		// Measured before this changed: a member holding roles/resourcemanager.projectIamAdmin
		// produced one privesc; the SAME binding carrying an IAM condition produced zero. The
		// condition in that test was request.time < 2030, which is satisfied right now — so the
		// principal could escalate to project admin today and the attack-path page said there
		// was no way to become admin. AWS reports the identical case as an edge marked
		// "config-possible; validate live", which is why InvPrivesc.Condition already exists and
		// already says "a config-possible escalation is never reported as confirmed".
		//
		// A condition we cannot evaluate is not a reason to report nothing. It is a reason to
		// report the path and say what is unresolved about it.
		// NOT "allowed, ignoring conditional" — that would readmit the firm-allow rule's whole
		// point. gcpiam reports conditional for three different reasons and only one of them
		// names a real permission: an unknown custom role and an unresolvable group leave us not
		// knowing WHAT the principal can do, and an escalation inferred from a role definition we
		// do not have is not evidence, it is the absence of it. A condition-gated grant is the
		// opposite — we know exactly which permission, and only when is open.
		permits := func(perm string) bool {
			req := gcpiam.Request{Member: member, Permission: perm}
			allowed, conditional := gcpiam.Permits(req, ps)
			if allowed && !conditional {
				return true
			}
			return gcpiam.PermitsGrantedButGated(req, ps)
		}
		firm := func(perm string) bool {
			allowed, conditional := gcpiam.Permits(gcpiam.Request{Member: member, Permission: perm}, ps)
			return allowed && !conditional
		}
		techs := gcpiam.DetectPrivesc(permits)
		if len(techs) == 0 {
			continue
		}
		// Definite only when a technique is reachable UNCONDITIONALLY. If every detected
		// escalation leans on a condition-gated permission, the edge is config-possible and
		// carries the reason — the same wording and the same threshold as the AWS path, so the
		// two clouds make the same claim about the same evidence.
		condition := ""
		if len(gcpiam.DetectPrivesc(firm)) == 0 {
			condition = "iam-condition-gated escalation (config-possible; validate live)"
		}
		names := make([]string, 0, len(techs))
		for _, t := range techs {
			names = append(names, t.Name)
		}
		inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{
			Principal: member, Target: cloudgraph.AdminID,
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

// UnknownRoles returns the roles appearing in the bindings whose permissions were not
// supplied, so a caller can state which part of the project it could not answer for.
// Empty means every role was resolvable — not that the project is safe.
func UnknownRoles(raw RawGCP) []string {
	seen, out := map[string]bool{}, []string{}
	for _, b := range raw.Bindings {
		switch b.Role {
		case "roles/owner", "roles/editor", "roles/viewer":
			continue // gcpiam understands the basic roles inline
		}
		if _, ok := raw.RoleDefs[b.Role]; ok || seen[b.Role] {
			continue
		}
		seen[b.Role] = true
		out = append(out, b.Role)
	}
	sort.Strings(out)
	return out
}
