// Package k8sinventory maps a Kubernetes cluster's RBAC + workload + exposure state into a
// cloudgraph.Inventory — the SAME attack-path fuel the AWS/Azure/GCP collectors produce.
//
// WHY THIS IS A MAPPER, NOT A NEW ENGINE. tridentsecurity.io/solutions/cloud lists Kubernetes as a
// first-class target beside AWS/Azure/GCP; we covered the three clouds and not the orchestrator that
// increasingly IS the cloud. The insight that makes it cheap: a cluster's security model is the same
// graph the engine already reasons over. A ServiceAccount is a principal, a Secret is a data resource,
// a RoleBinding is a grant, a Pod runs-as its ServiceAccount, a LoadBalancer Service is an
// internet→resource reach, and the RBAC verbs that let one identity become another (bind, escalate,
// impersonate, create-pod-with-privileged-SA) are privesc edges. So Kubernetes needs a fourth Build(),
// not a fourth engine — the reachability, privesc-chaining, pruning and remediation all come for free.
//
// GROUNDED (§10), exactly like the cloud collectors. Build asserts ONLY what the raw manifest proves: a
// grant edge only where a binding names a subject AND a role, a privesc edge only where the bound role
// actually carries an escalating verb on the right resource, an internet reach only where a Service is
// genuinely externally exposed (LoadBalancer / NodePort / an Ingress). A locked-down cluster yields a
// minimal graph with no internet edges and no privesc. The live client-go LIST calls (a real Fetcher
// over a read-only kubeconfig / in-cluster SA) are the credential-gated half; the mapper is pure and
// unit-tested with fixtures, and the raw shape doubles as a POST body so an external collector can ship
// it to the same ingest path as a posted cloud snapshot.
package k8sinventory

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// RawK8s mirrors the SUBSET of `kubectl get -o json` output the mapper reads. Pure data (no client-go
// types) so Build is fixture-testable and the k8s SDK stays behind a Fetcher. JSON tags make it a wire
// format: a CI job or the customer's own script with cluster read can POST this shape.
type RawK8s struct {
	Cluster         string       `json:"cluster"`
	ServiceAccounts []RawSA      `json:"service_accounts,omitempty"`
	Roles           []RawRole    `json:"roles,omitempty"`    // Role + ClusterRole, flattened
	Bindings        []RawBinding `json:"bindings,omitempty"` // RoleBinding + ClusterRoleBinding
	Pods            []RawPod     `json:"pods,omitempty"`
	Services        []RawService `json:"services,omitempty"`
	Secrets         []RawSecret  `json:"secrets,omitempty"`
}

// RawSA is a ServiceAccount — a principal.
type RawSA struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// RawRole is a Role or ClusterRole with its rules. Cluster=true means it applies cluster-wide.
type RawRole struct {
	Namespace string    `json:"namespace,omitempty"` // empty for ClusterRole
	Name      string    `json:"name"`
	Cluster   bool      `json:"cluster,omitempty"`
	Rules     []RawRule `json:"rules,omitempty"`
}

// RawRule is one policy rule: verbs over resources (optionally named). Mirrors rbac.v1 PolicyRule.
type RawRule struct {
	Verbs         []string `json:"verbs,omitempty"`
	Resources     []string `json:"resources,omitempty"`
	ResourceNames []string `json:"resource_names,omitempty"`
	APIGroups     []string `json:"api_groups,omitempty"`
}

// RawBinding binds subjects (SAs/users/groups) to a role.
type RawBinding struct {
	Namespace string       `json:"namespace,omitempty"`
	Name      string       `json:"name"`
	RoleRef   string       `json:"role_ref"` // the Role/ClusterRole name it grants
	Subjects  []RawSubject `json:"subjects,omitempty"`
}

// RawSubject is who a binding grants to.
type RawSubject struct {
	Kind      string `json:"kind"` // ServiceAccount | User | Group
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// RawPod is a workload; it runs AS its ServiceAccount and may mount a Secret.
type RawPod struct {
	Namespace      string   `json:"namespace"`
	Name           string   `json:"name"`
	ServiceAccount string   `json:"service_account,omitempty"`
	Image          string   `json:"image,omitempty"`
	Privileged     bool     `json:"privileged,omitempty"` // a privileged securityContext / hostPID / hostNetwork
	MountedSecrets []string `json:"mounted_secrets,omitempty"`
}

// RawService exposes pods; Type LoadBalancer/NodePort (or ExternalIP) is internet-reachable.
type RawService struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Type      string `json:"type,omitempty"`     // ClusterIP | NodePort | LoadBalancer | ExternalName
	External  bool   `json:"external,omitempty"` // a LB with an ingress address / an explicit externalIP / an Ingress
	Selector  string `json:"selector,omitempty"` // "k=v,k2=v2" — informational
}

// RawSecret is a data store; Sensitive marks credential/token material.
type RawSecret struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Type      string `json:"type,omitempty"` // kubernetes.io/service-account-token, Opaque, dockerconfigjson…
}

// nsName is the stable node id for a namespaced object: "ns/kind/name".
func nsName(ns, kind, name string) string {
	if ns == "" {
		ns = "cluster"
	}
	return ns + "/" + kind + "/" + name
}

// escalatingVerb reports whether a rule grants an RBAC PRIVILEGE-ESCALATION verb — the moves that let a
// principal gain rights it was not directly given. This is the Kubernetes analogue of the PMapper IAM
// privesc set, and it is deliberately conservative: only the verbs that are escalations by construction.
func escalatingRule(r RawRule) (string, bool) {
	has := func(list []string, want ...string) bool {
		for _, v := range list {
			lv := strings.ToLower(v)
			if lv == "*" {
				return true
			}
			for _, w := range want {
				if lv == w {
					return true
				}
			}
		}
		return false
	}
	res := func(want ...string) bool { return has(r.Resources, want...) }

	switch {
	case has(r.Verbs, "bind") && res("clusterroles", "roles"):
		return "can bind roles to itself/others (rbac bind escalation)", true
	case has(r.Verbs, "escalate") && res("clusterroles", "roles"):
		return "holds the rbac escalate verb — can grant itself any permission", true
	case has(r.Verbs, "impersonate") && res("users", "groups", "serviceaccounts"):
		return "can impersonate other identities", true
	case has(r.Verbs, "create") && res("pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "replicasets"):
		return "can create pods — can schedule a pod with a more-privileged ServiceAccount", true
	case (has(r.Verbs, "create", "update", "patch")) && res("*") && (len(r.APIGroups) == 0 || has(r.APIGroups, "*", "")):
		return "holds write on all resources (cluster-admin-equivalent)", true
	case has(r.Verbs, "get", "list", "watch") && res("secrets"):
		return "can read Secrets — can steal any ServiceAccount token they hold", true
	}
	return "", false
}

// Build maps the raw cluster subset into a cloudgraph.Inventory. Pure + grounded (§10).
func Build(raw RawK8s) cloudgraph.Inventory {
	inv := cloudgraph.Inventory{AccountID: raw.Cluster, Provider: "kubernetes"}

	// Roles by name → for resolving a binding's role rules into privesc edges.
	roleByName := make(map[string]RawRole, len(raw.Roles))
	for _, r := range raw.Roles {
		roleByName[r.Name] = r
	}

	for _, sa := range raw.ServiceAccounts {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: nsName(sa.Namespace, "sa", sa.Name), Kind: cloudgraph.KindPrincipal,
			Type: "k8s_service_account", Name: sa.Name, Region: sa.Namespace,
		})
	}
	for _, sec := range raw.Secrets {
		sensitive := cloudgraph.Sensitivity("")
		if strings.Contains(strings.ToLower(sec.Type), "token") || strings.Contains(strings.ToLower(sec.Type), "dockerconfig") {
			sensitive = cloudgraph.SensHigh
		}
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: nsName(sec.Namespace, "secret", sec.Name), Kind: cloudgraph.KindData,
			Type: "k8s_secret", Name: sec.Name, Region: sec.Namespace, Sensitive: sensitive,
		})
	}
	for _, p := range raw.Pods {
		pid := nsName(p.Namespace, "pod", p.Name)
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: pid, Kind: cloudgraph.KindResource, Type: "k8s_pod", Name: p.Name,
			Region: p.Namespace, Image: p.Image, Privileged: p.Privileged,
		})
		// A pod RUNS AS its ServiceAccount — the identity an attacker inherits on pod compromise.
		if p.ServiceAccount != "" {
			inv.RunsAs = append(inv.RunsAs, cloudgraph.InvRunsAs{
				Compute: pid, Principal: nsName(p.Namespace, "sa", p.ServiceAccount),
			})
		}
		// A mounted Secret is reachable from the pod → lateral movement to whatever it authenticates.
		for _, s := range p.MountedSecrets {
			inv.Secrets = append(inv.Secrets, cloudgraph.InvSecretAccess{
				Principal: pid, Secret: nsName(p.Namespace, "secret", s),
			})
		}
	}

	// Bindings become GRANT edges (subject → the role's authority) and, where the role carries an
	// escalating verb, PRIVESC edges. Grounded: only a binding that names both a subject and a resolvable
	// role produces an edge, and privesc only where the bound role's rules actually escalate.
	for _, b := range raw.Bindings {
		role, ok := roleByName[b.RoleRef]
		for _, subj := range b.Subjects {
			if subj.Name == "" {
				continue
			}
			var sid string
			switch strings.ToLower(subj.Kind) {
			case "serviceaccount":
				sid = nsName(orNs(subj.Namespace, b.Namespace), "sa", subj.Name)
			default:
				sid = "identity/" + strings.ToLower(subj.Kind) + "/" + subj.Name
			}
			// The grant target is the role itself as an authority node — enough to chain, and honest:
			// we do not invent access to a specific resource the rule did not name.
			inv.Grants = append(inv.Grants, cloudgraph.InvGrant{
				Principal: sid, Resource: "role/" + b.RoleRef,
			})
			if ok {
				for _, rule := range role.Rules {
					if detail, esc := escalatingRule(rule); esc {
						inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{
							Principal: sid, Target: nsName("cluster", "role", "cluster-admin"),
							Detail: "via " + b.RoleRef + ": " + detail,
						})
						break // one privesc edge per (subject, binding) — the detail names the verb
					}
				}
			}
		}
	}

	// Externally-exposed Services are the internet entry point.
	for _, svc := range raw.Services {
		sid := nsName(svc.Namespace, "svc", svc.Name)
		external := svc.External || strings.EqualFold(svc.Type, "LoadBalancer") || strings.EqualFold(svc.Type, "NodePort")
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: sid, Kind: cloudgraph.KindResource, Type: "k8s_service", Name: svc.Name,
			Region: svc.Namespace, Public: external,
		})
		if external {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: sid})
		}
	}

	return inv
}

// orNs returns the subject's own namespace, falling back to the binding's (a RoleBinding subject may
// omit its namespace, defaulting to the binding's).
func orNs(subjectNS, bindingNS string) string {
	if subjectNS != "" {
		return subjectNS
	}
	return bindingNS
}
