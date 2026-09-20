package connector

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/k8sinventory"
)

// A complete cluster manifest declares nothing. The mirror matters as much as the gaps: a note that
// fires on a healthy cluster is one people learn to skip, and then the real one goes unread too.
func TestCoverK8s_ACompleteSnapshotDeclaresNothing(t *testing.T) {
	raw := k8sinventory.RawK8s{
		Cluster:         "prod",
		ServiceAccounts: []k8sinventory.RawSA{{Namespace: "app", Name: "api"}},
		Roles: []k8sinventory.RawRole{{
			Name: "api-role", Namespace: "app",
			Rules: []k8sinventory.RawRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}},
		}},
		Bindings: []k8sinventory.RawBinding{{
			Namespace: "app", Name: "api-rb", RoleRef: "api-role",
			Subjects: []k8sinventory.RawSubject{{Kind: "ServiceAccount", Namespace: "app", Name: "api"}},
		}},
		Services: []k8sinventory.RawService{{Namespace: "app", Name: "api-svc", Type: "ClusterIP"}},
	}
	if c := CoverK8s(raw); !c.Complete() {
		t.Fatalf("a complete manifest reported gaps: %v", c.Notes)
	}
}

// THE DEFECT THIS CLOSES. The k8s branch returned an empty coverage, so a manifest missing the very
// objects the analysis reads produced zero privesc, zero internet reach, and no note — and on an
// attack-path page zero reads as "nobody can become admin in this cluster".
func TestCoverK8s_MissingRBACIsDeclaredRatherThanReadingClean(t *testing.T) {
	// Service accounts and pods, but no RBAC at all: the shape a `kubectl get sa,pods` collector
	// produces when somebody forgets roles and bindings.
	raw := k8sinventory.RawK8s{
		Cluster:         "prod",
		ServiceAccounts: []k8sinventory.RawSA{{Namespace: "app", Name: "api"}},
		Pods:            []k8sinventory.RawPod{{Namespace: "app", Name: "api-1", ServiceAccount: "api"}},
	}
	c := CoverK8s(raw)
	if c.Complete() {
		t.Fatal("a manifest with no roles, no bindings and no services reported full coverage")
	}
	for _, want := range []string{"rbac-roles", "rbac-bindings", "exposure"} {
		if _, ok := c.Notes[want]; !ok {
			t.Errorf("no %q note — its absence is what makes an unread cluster look clean", want)
		}
	}
	// Every note names the field to populate: the caller is usually a kubectl script, and "something
	// is missing" is not something a script author can act on.
	for k, note := range c.Notes {
		if !strings.Contains(note, "Populate") && !strings.Contains(note, "Include") {
			t.Errorf("note %q does not say what to send: %q", k, note)
		}
	}
	if !strings.Contains(c.Summary(), "UNREAD, not safe") {
		t.Errorf("summary does not carry the refusal: %q", c.Summary())
	}
}

// A binding pointing at a role we do not have is the cluster twin of GCP's unresolvable custom role:
// the grant is real, the verbs are unknown, and no edge is built — so the principals somebody
// deliberately granted something to are exactly the ones under-reported.
func TestCoverK8s_ABindingToAnAbsentRoleIsNamed(t *testing.T) {
	raw := k8sinventory.RawK8s{
		ServiceAccounts: []k8sinventory.RawSA{{Namespace: "app", Name: "api"}},
		Roles:           []k8sinventory.RawRole{{Name: "known", Rules: []k8sinventory.RawRule{{Verbs: []string{"get"}}}}},
		Bindings: []k8sinventory.RawBinding{
			{Name: "ok-rb", RoleRef: "known"},
			{Name: "dangling-rb", RoleRef: "cluster-admin"},
		},
		Services: []k8sinventory.RawService{{Namespace: "app", Name: "svc"}},
	}
	c := CoverK8s(raw)
	note, ok := c.Notes["unresolved-roles"]
	if !ok {
		t.Fatalf("a binding to an absent role was not declared: %v", c.Notes)
	}
	if !strings.Contains(note, "cluster-admin") {
		t.Errorf("the note does not name the missing role: %q", note)
	}
	if strings.Contains(note, "ok-rb") {
		t.Errorf("a resolvable binding was reported as unresolved: %q", note)
	}
}

// A ClusterRole carries no namespace, so matching roleRefs on namespace as well as name would report
// every legitimate cluster-role binding as unresolved — a note that fires constantly is not read.
func TestCoverK8s_AClusterRoleBindingFromANamespaceIsNotUnresolved(t *testing.T) {
	raw := k8sinventory.RawK8s{
		ServiceAccounts: []k8sinventory.RawSA{{Namespace: "app", Name: "api"}},
		Roles:           []k8sinventory.RawRole{{Name: "view", Cluster: true, Rules: []k8sinventory.RawRule{{Verbs: []string{"get"}}}}},
		Bindings:        []k8sinventory.RawBinding{{Namespace: "app", Name: "view-rb", RoleRef: "view"}},
		Services:        []k8sinventory.RawService{{Namespace: "app", Name: "svc"}},
	}
	if note, ok := CoverK8s(raw).Notes["unresolved-roles"]; ok {
		t.Errorf("a namespaced binding to a ClusterRole was called unresolved: %q", note)
	}
}

// An empty secrets or pods list is NOT reported: a cluster genuinely may have neither, and a note
// there would fire on healthy clusters. RBAC and services are different — without them the result
// changes MEANING rather than content.
func TestCoverK8s_DoesNotFireOnLegitimatelyEmptyCollections(t *testing.T) {
	raw := k8sinventory.RawK8s{
		ServiceAccounts: []k8sinventory.RawSA{{Namespace: "app", Name: "api"}},
		Roles:           []k8sinventory.RawRole{{Name: "r", Rules: []k8sinventory.RawRule{{Verbs: []string{"get"}}}}},
		Bindings:        []k8sinventory.RawBinding{{Name: "rb", RoleRef: "r"}},
		Services:        []k8sinventory.RawService{{Namespace: "app", Name: "svc"}},
		// no pods, no secrets
	}
	if c := CoverK8s(raw); !c.Complete() {
		t.Errorf("fired on a cluster with no pods or secrets, which is a legitimate state: %v", c.Notes)
	}
}
