package k8sinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func countPrivesc(inv cloudgraph.Inventory) int { return len(inv.Privescs) }
func hasReachFromInternet(inv cloudgraph.Inventory, to string) bool {
	for _, r := range inv.Reaches {
		if r.From == cloudgraph.InternetID && r.To == to {
			return true
		}
	}
	return false
}

// THE ONE THAT MATTERS: a locked-down cluster produces NO privesc and NO internet edges. If a benign
// cluster lights up, every finding on a real one is suspect.
func TestBuild_LockedDownClusterIsQuiet(t *testing.T) {
	inv := Build(RawK8s{
		Cluster:         "prod",
		ServiceAccounts: []RawSA{{Namespace: "app", Name: "web"}},
		Roles: []RawRole{{Namespace: "app", Name: "reader", Rules: []RawRule{
			{Verbs: []string{"get", "list"}, Resources: []string{"pods"}}, // read pods only — not an escalation
		}}},
		Bindings: []RawBinding{{Namespace: "app", Name: "b1", RoleRef: "reader",
			Subjects: []RawSubject{{Kind: "ServiceAccount", Namespace: "app", Name: "web"}}}},
		Services: []RawService{{Namespace: "app", Name: "web", Type: "ClusterIP"}}, // internal only
		Secrets:  []RawSecret{{Namespace: "app", Name: "cfg", Type: "Opaque"}},
	})
	if n := countPrivesc(inv); n != 0 {
		t.Errorf("locked-down cluster produced %d privesc edge(s) — a read-only role is not an escalation: %+v", n, inv.Privescs)
	}
	for _, r := range inv.Reaches {
		if r.From == cloudgraph.InternetID {
			t.Errorf("ClusterIP service was marked internet-reachable: %+v", r)
		}
	}
}

// A ServiceAccount bound to a role that can CREATE PODS is a real privesc — schedule a pod with a
// better SA. This must produce an edge.
func TestBuild_CreatePodsIsPrivesc(t *testing.T) {
	inv := Build(RawK8s{
		Cluster:         "prod",
		ServiceAccounts: []RawSA{{Namespace: "ci", Name: "runner"}},
		Roles: []RawRole{{Name: "deployer", Cluster: true, Rules: []RawRule{
			{Verbs: []string{"create"}, Resources: []string{"pods"}},
		}}},
		Bindings: []RawBinding{{Name: "b", RoleRef: "deployer",
			Subjects: []RawSubject{{Kind: "ServiceAccount", Namespace: "ci", Name: "runner"}}}},
	})
	if countPrivesc(inv) == 0 {
		t.Error("create-pods role produced no privesc edge — that is the canonical k8s escalation")
	}
}

// Reading Secrets is a privesc (steal any SA token they hold). rbac 'escalate'/'bind'/'impersonate' too.
func TestBuild_SecretReadAndRbacVerbsArePrivesc(t *testing.T) {
	for _, rule := range []RawRule{
		{Verbs: []string{"get"}, Resources: []string{"secrets"}},
		{Verbs: []string{"escalate"}, Resources: []string{"clusterroles"}},
		{Verbs: []string{"bind"}, Resources: []string{"roles"}},
		{Verbs: []string{"impersonate"}, Resources: []string{"users"}},
	} {
		inv := Build(RawK8s{
			Cluster:         "c",
			ServiceAccounts: []RawSA{{Namespace: "x", Name: "sa"}},
			Roles:           []RawRole{{Name: "r", Cluster: true, Rules: []RawRule{rule}}},
			Bindings: []RawBinding{{Name: "b", RoleRef: "r",
				Subjects: []RawSubject{{Kind: "ServiceAccount", Namespace: "x", Name: "sa"}}}},
		})
		if countPrivesc(inv) == 0 {
			t.Errorf("verb %v on %v was not treated as a privesc", rule.Verbs, rule.Resources)
		}
	}
}

// A LoadBalancer service is the internet entry point; a pod runs-as its SA (the identity inherited on
// compromise). The full chain — internet → svc, pod → sa — is what makes an attack path.
func TestBuild_ExposureAndRunsAs(t *testing.T) {
	inv := Build(RawK8s{
		Cluster:         "prod",
		ServiceAccounts: []RawSA{{Namespace: "app", Name: "api"}},
		Pods:            []RawPod{{Namespace: "app", Name: "api-0", ServiceAccount: "api", MountedSecrets: []string{"db"}}},
		Services:        []RawService{{Namespace: "app", Name: "api", Type: "LoadBalancer", External: true}},
		Secrets:         []RawSecret{{Namespace: "app", Name: "db", Type: "Opaque"}},
	})
	if !hasReachFromInternet(inv, "app/svc/api") {
		t.Error("LoadBalancer service was not marked internet-reachable")
	}
	foundRunsAs := false
	for _, ra := range inv.RunsAs {
		if ra.Compute == "app/pod/api-0" && ra.Principal == "app/sa/api" {
			foundRunsAs = true
		}
	}
	if !foundRunsAs {
		t.Errorf("pod→ServiceAccount runs-as edge missing: %+v", inv.RunsAs)
	}
	foundSecret := false
	for _, s := range inv.Secrets {
		if s.Principal == "app/pod/api-0" && s.Secret == "app/secret/db" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Errorf("pod→secret access edge missing: %+v", inv.Secrets)
	}
}

// A token-type Secret is high-sensitivity data; a binding that names no resolvable role produces no
// grant. Grounded: no phantom edges.
func TestBuild_TokenSecretSensitiveAndNoPhantomGrant(t *testing.T) {
	inv := Build(RawK8s{
		Cluster: "c",
		Secrets: []RawSecret{{Namespace: "kube-system", Name: "sa-token", Type: "kubernetes.io/service-account-token"}},
		Bindings: []RawBinding{{Name: "dangling", RoleRef: "does-not-exist",
			Subjects: []RawSubject{{Kind: "ServiceAccount", Namespace: "x", Name: "sa"}}}},
	})
	var tokenSensitive bool
	for _, r := range inv.Resources {
		if r.Type == "k8s_secret" && r.Sensitive == cloudgraph.SensHigh {
			tokenSensitive = true
		}
	}
	if !tokenSensitive {
		t.Error("a service-account-token Secret was not marked high-sensitivity")
	}
	// A binding to a missing role still grants the (named) role authority — but produces NO privesc,
	// because we cannot see the role's rules.
	if countPrivesc(inv) != 0 {
		t.Errorf("privesc asserted from a role we could not resolve: %+v", inv.Privescs)
	}
}

// The provider must be "kubernetes" so the engine + UI route it correctly.
func TestBuild_ProviderIsKubernetes(t *testing.T) {
	if inv := Build(RawK8s{Cluster: "c"}); inv.Provider != "kubernetes" {
		t.Errorf("provider = %q, want kubernetes", inv.Provider)
	}
}
