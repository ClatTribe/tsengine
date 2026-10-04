package gcpfetch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
)

// fakeGCP serves the Google APIs the fetcher reads, from a route table a test can override.
type fakeGCP struct {
	srv    *httptest.Server
	routes map[string]any // "METHOD path" → JSON body (or int status for an error)
}

func newFake(t *testing.T) *fakeGCP {
	t.Helper()
	f := &fakeGCP{routes: baseRoutes()}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		if q := r.URL.Query().Get("pageToken"); q != "" {
			key += "?pageToken=" + q
		}
		v, ok := f.routes[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"message":"not found: ` + key + `"}}`))
			return
		}
		switch b := v.(type) {
		case int:
			w.WriteHeader(b)
			_, _ = w.Write([]byte(`{"error":{"message":"permission denied"}}`))
		case string:
			_, _ = w.Write([]byte(b))
		default:
			_ = json.NewEncoder(w).Encode(b)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGCP) fetcher() *Fetcher {
	u := f.srv.URL
	return &Fetcher{Project: "acme-prod", Client: f.srv.Client(), API: Endpoints{CRM: u, IAM: u, Compute: u, Storage: u}}
}

const net1 = "https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/default"

func baseRoutes() map[string]any {
	return map[string]any{
		"POST /v1/projects/acme-prod:getIamPolicy": map[string]any{"bindings": []map[string]any{
			{"role": "roles/owner", "members": []string{"user:ada@acme.example"}},
			{"role": "roles/owner", "members": []string{"user:temp@acme.example"}, "condition": map[string]string{"expression": "request.time < timestamp('2026-12-01T00:00:00Z')"}},
			{"role": "roles/editor", "members": []string{"serviceAccount:deploy@acme-prod.iam.gserviceaccount.com"}},
			{"role": "roles/iam.serviceAccountTokenCreator", "members": []string{"user:bo@acme.example"}},
			{"role": "projects/acme-prod/roles/customDeployer", "members": []string{"group:devs@acme.example"}},
		}},
		"GET /v1/projects/acme-prod/serviceAccounts": map[string]any{"accounts": []map[string]any{
			{"email": "deploy@acme-prod.iam.gserviceaccount.com"},
		}, "nextPageToken": "p2"},
		"GET /v1/projects/acme-prod/serviceAccounts?pageToken=p2": map[string]any{"accounts": []map[string]any{
			{"email": "ci@acme-prod.iam.gserviceaccount.com"},
			{"email": "old@acme-prod.iam.gserviceaccount.com", "disabled": true},
		}},
		"POST /v1/projects/acme-prod/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com:getIamPolicy": map[string]any{},
		"POST /v1/projects/acme-prod/serviceAccounts/ci@acme-prod.iam.gserviceaccount.com:getIamPolicy": map[string]any{"bindings": []map[string]any{
			{"role": "roles/iam.workloadIdentityUser", "members": []string{"principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gh/*"}},
		}},
		"GET /v1/roles/iam.serviceAccountTokenCreator":    map[string]any{"includedPermissions": []string{"iam.serviceAccounts.getAccessToken"}},
		"GET /v1/roles/iam.workloadIdentityUser":          map[string]any{"includedPermissions": []string{"iam.serviceAccounts.getAccessToken"}},
		"GET /v1/projects/acme-prod/roles/customDeployer": map[string]any{"includedPermissions": []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"}},
		"GET /compute/v1/projects/acme-prod/global/firewalls": map[string]any{"items": []map[string]any{
			{"name": "ssh-world", "network": net1, "direction": "INGRESS", "sourceRanges": []string{"0.0.0.0/0"}, "targetTags": []string{"bastion"},
				"allowed": []map[string]any{{"IPProtocol": "tcp", "ports": []string{"22"}}}},
			{"name": "app-corp", "network": net1, "direction": "INGRESS", "sourceRanges": []string{"10.0.0.0/8"},
				"allowed": []map[string]any{{"IPProtocol": "tcp", "ports": []string{"8080"}}}},
			{"name": "off", "network": net1, "direction": "INGRESS", "disabled": true, "sourceRanges": []string{"0.0.0.0/0"},
				"allowed": []map[string]any{{"IPProtocol": "all"}}},
		}},
		"GET /compute/v1/projects/acme-prod/aggregated/instances": map[string]any{"items": map[string]any{
			"zones/us-central1-a": map[string]any{"instances": []map[string]any{
				{"name": "bastion-1", "zone": "projects/acme-prod/zones/us-central1-a", "tags": map[string]any{"items": []string{"bastion"}},
					"networkInterfaces": []map[string]any{{"network": net1, "accessConfigs": []map[string]any{{"natIP": "34.1.2.3"}}}}},
				{"name": "app-1", "zone": "projects/acme-prod/zones/us-central1-a",
					"networkInterfaces": []map[string]any{{"network": net1, "accessConfigs": []map[string]any{{"natIP": "34.1.2.4"}}}}},
			}},
			"zones/europe-west1-b": map[string]any{"warning": map[string]any{"code": "NO_RESULTS_ON_PAGE"}},
		}},
		"GET /storage/v1/b": map[string]any{"items": []map[string]any{
			{"name": "acme-exports", "location": "US", "labels": map[string]string{"data-sensitivity": "customer"}},
			{"name": "acme-site", "location": "EU"},
		}},
		"GET /storage/v1/b/acme-exports/iam": map[string]any{"bindings": []map[string]any{{"role": "roles/storage.objectViewer", "members": []string{"allUsers"}}}},
		"GET /storage/v1/b/acme-site/iam":    map[string]any{"bindings": []map[string]any{{"role": "roles/storage.objectViewer", "members": []string{"projectViewer:acme-prod"}}}},
		"GET /v1/projects/acme-prod":         map[string]any{"projectNumber": "123"},
		"GET /v1/projects/acme-prod/locations/global/workloadIdentityPools": map[string]any{"workloadIdentityPools": []map[string]any{
			{"name": "projects/123/locations/global/workloadIdentityPools/gh"},
		}},
		"GET /v1/projects/123/locations/global/workloadIdentityPools/gh/providers": map[string]any{"workloadIdentityPoolProviders": []map[string]any{
			{"name": "projects/123/locations/global/workloadIdentityPools/gh/providers/github", "attributeMapping": map[string]string{"google.subject": "assertion.sub"},
				"oidc": map[string]any{"issuerUri": "https://token.actions.githubusercontent.com"}},
		}},
	}
}

func TestFetch_ReadsTheProjectIntoTheIngestShape(t *testing.T) {
	f := newFake(t)
	res, err := f.fetcher().Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("a fully readable project reported skipped surfaces: %v", res.Skipped)
	}
	raw := res.Raw
	// Members: users/groups, admin only for an UNCONDITIONED basic write role.
	admin := map[string]bool{}
	for _, m := range raw.Members {
		admin[m.Member] = m.Admin
	}
	if !admin["user:ada@acme.example"] || admin["user:temp@acme.example"] || admin["user:bo@acme.example"] {
		t.Errorf("admin flags = %v; owner unconditioned is admin, a time-boxed owner and a token creator are not", admin)
	}
	// Service accounts: paginated, disabled skipped, project-level token creators impersonate every SA.
	if len(raw.ServiceAccounts) != 2 {
		t.Fatalf("service accounts = %+v; want deploy + ci (the disabled one skipped, both pages read)", raw.ServiceAccounts)
	}
	for _, sa := range raw.ServiceAccounts {
		if !contains(sa.Impersonators, "user:bo@acme.example") {
			t.Errorf("%s: the project-level token creator is not listed as an impersonator: %v", sa.Email, sa.Impersonators)
		}
		if sa.Email == "deploy@acme-prod.iam.gserviceaccount.com" && !sa.Admin {
			t.Error("an SA holding roles/editor was not marked admin")
		}
		if sa.Email == "ci@acme-prod.iam.gserviceaccount.com" && len(sa.Bindings) != 1 {
			t.Errorf("the SA-level policy was not carried (gcpwif needs it): %+v", sa.Bindings)
		}
	}
	// Role definitions for every non-basic role in use, including custom ones.
	for _, r := range []string{"projects/acme-prod/roles/customDeployer", "roles/iam.serviceAccountTokenCreator", "roles/iam.workloadIdentityUser"} {
		if _, ok := raw.RoleDefs[r]; !ok {
			t.Errorf("role definition %s was not read", r)
		}
	}
	if _, ok := raw.RoleDefs["roles/owner"]; ok {
		t.Error("a basic role was fetched — gcpiam understands those inline")
	}
	// Instances: the world-open SSH rule applies to the tagged bastion only; the corp-only rule is not
	// internet exposure; the disabled any-port rule is ignored.
	inst := map[string]gcpinventory.RawGCPInstance{}
	for _, in := range raw.Instances {
		inst[in.Name] = in
	}
	if b := inst["bastion-1"]; !b.ExternalIP || b.ServicePort != 22 || b.Region != "us-central1-a" {
		t.Errorf("bastion = %+v; want external, port 22 from the world-open rule", b)
	}
	if a := inst["app-1"]; a.ServicePort != 0 {
		t.Errorf("app-1 = %+v; only a corporate-range rule applies, so no world-open port", a)
	}
	// Buckets: public by allUsers, sensitive only by the declared label.
	bk := map[string]gcpinventory.RawGCPBucket{}
	for _, b := range raw.Buckets {
		bk[b.Name] = b
	}
	if !bk["acme-exports"].Public || !bk["acme-exports"].Sensitive || bk["acme-site"].Public || bk["acme-site"].Sensitive {
		t.Errorf("buckets = %+v", bk)
	}
	// Workload identity: the provider, with its (absent) condition.
	if len(raw.WIFProviders) != 1 || raw.WIFProviders[0].ProjectNumber != "123" || raw.WIFProviders[0].AttributeCondition != "" {
		t.Errorf("wif providers = %+v", raw.WIFProviders)
	}

	// And it reaches the PRODUCT graph: the fetched shape builds an internet edge to the bastion.
	inv := gcpinventory.Build(raw)
	reach := false
	for _, r := range inv.Reaches {
		if r.From != cloudgraph.InternetID {
			continue
		}
		if r.To == "bastion-1" {
			reach = true
		}
		if r.To == "app-1" {
			t.Error("app-1 got an internet reach edge from a corporate-only firewall rule")
		}
	}
	if !reach {
		t.Error("the live-fetched project produced no internet reach edge to the world-open bastion")
	}
}

func TestFetch_ProjectPolicyIsTheFloor(t *testing.T) {
	f := newFake(t)
	f.routes["POST /v1/projects/acme-prod:getIamPolicy"] = http.StatusForbidden
	if _, err := f.fetcher().Fetch(context.Background()); err == nil {
		t.Error("a project whose IAM policy cannot be read was returned as a result — it would read as nobody can do anything")
	}
}

func TestFetch_NamesWhatItCouldNotRead(t *testing.T) {
	f := newFake(t)
	delete(f.routes, "GET /v1/projects/acme-prod/roles/customDeployer")
	f.routes["GET /compute/v1/projects/acme-prod/global/firewalls"] = http.StatusForbidden
	f.routes["GET /storage/v1/b/acme-exports/iam"] = http.StatusForbidden
	f.routes["GET /v1/projects/acme-prod/serviceAccounts?pageToken=p2"] = http.StatusInternalServerError
	res, err := f.fetcher().Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"role-definitions": "customDeployer",
		"firewalls":        "no instance's internet reachability was evaluated",
		"bucket-policies":  "acme-exports",
		"service-accounts": "HTTP 500",
	} {
		if !strings.Contains(res.Skipped[k], want) {
			t.Errorf("Skipped[%s] = %q, want it to mention %q", k, res.Skipped[k], want)
		}
	}
	if _, ok := res.Raw.RoleDefs["projects/acme-prod/roles/customDeployer"]; ok {
		t.Error("an unread role definition was recorded")
	}
	for _, in := range res.Raw.Instances {
		if in.ServicePort != 0 {
			t.Errorf("%s got a service port with its firewalls unread", in.Name)
		}
	}
	for _, b := range res.Raw.Buckets {
		if b.Name == "acme-exports" && b.Public {
			t.Error("a bucket whose policy could not be read was reported public")
		}
	}
	if len(res.Raw.ServiceAccounts) != 0 || res.Covers("service-accounts") {
		t.Error("a service-account list cut short by a page error was treated as complete")
	}
}

func TestFetch_HTMLIsNotAnEmptyResult(t *testing.T) {
	f := newFake(t)
	f.routes["GET /storage/v1/b"] = "<html>sign in</html>"
	res, err := f.fetcher().Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Skipped["storage"], "not the JSON") {
		t.Errorf("an HTML 200 was read as an empty bucket list: %v", res.Skipped)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
