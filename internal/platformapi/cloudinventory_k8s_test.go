package platformapi

import (
	"strings"
	"testing"
)

// A collector nothing calls is the pattern this repo keeps catching (the Shipped column exists for it),
// so the wiring gets its own test: ?provider=kubernetes must reach the k8s mapper and produce the same
// Inventory shape the engine reasons over.
func TestBuildCloudInventory_KubernetesIsRoutable(t *testing.T) {
	body := []byte(`{
	  "cluster":"prod",
	  "service_accounts":[{"namespace":"ci","name":"runner"}],
	  "roles":[{"name":"deployer","cluster":true,"rules":[{"verbs":["create"],"resources":["pods"]}]}],
	  "bindings":[{"name":"b","role_ref":"deployer","subjects":[{"kind":"ServiceAccount","namespace":"ci","name":"runner"}]}],
	  "services":[{"namespace":"app","name":"web","type":"LoadBalancer","external":true}]
	}`)
	for _, provider := range []string{"kubernetes", "k8s"} {
		inv, err := buildCloudInventory(provider, body)
		if err != nil {
			t.Fatalf("provider %q: %v", provider, err)
		}
		if inv.Provider != "kubernetes" {
			t.Errorf("provider %q produced Provider=%q", provider, inv.Provider)
		}
		if len(inv.Privescs) == 0 {
			t.Errorf("provider %q: create-pods binding produced no privesc edge — the mapper is not being reached", provider)
		}
		if len(inv.Reaches) == 0 {
			t.Errorf("provider %q: LoadBalancer produced no internet edge", provider)
		}
	}
}

// The error must name what IS supported, or a caller cannot correct the request.
func TestBuildCloudInventory_UnknownProviderListsKubernetes(t *testing.T) {
	_, err := buildCloudInventory("openstack", []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	if !strings.Contains(err.Error(), "kubernetes") {
		t.Errorf("the error does not mention kubernetes as supported: %v", err)
	}
}
