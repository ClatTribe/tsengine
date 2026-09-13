package gcpinventory

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// Every technique Rhino's catalogue named must produce a privesc edge through the REAL ingest,
// not only through gcpiam.DetectPrivesc.
//
// WHY THIS FILE EXISTS. The eight techniques that took the Rhino GCP score from 65.2% to 100%
// were added in the SAME commit as the bench that measures them (#1270), and nothing drove any
// of them through Build. So the published recall rested entirely on a direct call to the
// catalogue, and a technique dead in production — a permission the role resolver spells
// differently, an entry the firm-allow rule silently refuses — would have left the bench reading
// 100% while a customer's project produced no edge. That is the built-but-unwired shape, with a
// benchmark number sitting on top of it.
//
// The AWS side got this guard when CloudGoat's misses were closed; this is its GCP twin.
func TestBuild_RhinoCataloguedTechniquesProduceAPrivescEdge(t *testing.T) {
	cases := []struct {
		rhino    string // Rhino's own name for the method — the answer key's vocabulary
		perms    []string
		wantTech string
	}{
		{"SetProjectIAMPolicy", []string{"resourcemanager.projects.setIamPolicy"}, "SetIamPolicy"},
		{"SetServiceAccountIAMPolicy", []string{"iam.serviceAccounts.setIamPolicy"}, "SetServiceAccountIamPolicy"},
		{"CreateServiceAccountKey", []string{"iam.serviceAccountKeys.create"}, "ServiceAccountKeyCreate"},
		{"GetServiceAccountAccessToken", []string{"iam.serviceAccounts.getAccessToken"}, "ServiceAccountGetAccessToken"},
		{"ServiceAccountSignBlob", []string{"iam.serviceAccounts.signBlob"}, "ServiceAccountSignBlobOrJwt"},
		{"ServiceAccountImplicitDelegation", []string{"iam.serviceAccounts.implicitDelegation"}, "ServiceAccountImplicitDelegation"},
		{"UpdateIAMRole", []string{"iam.roles.update"}, "UpdateCustomRole"},
		{"RCECloudBuildBuildServer", []string{"cloudbuild.builds.create"}, "CloudBuildPrivesc"},
		{"CreateDeploymentManagerDeployment", []string{"deploymentmanager.deployments.create"}, "DeploymentManagerPrivesc"},
		{"CreateServiceAccountHMACKey", []string{"storage.hmacKeys.create"}, "CreateServiceAccountHMACKey"},
		{"CreateAPIKey", []string{"serviceusage.apiKeys.create"}, "CreateAPIKey"},
		{"ViewExistingAPIKeys", []string{"serviceusage.apiKeys.list"}, "ViewExistingAPIKeys"},
		{"SetOrgPolicyConstraints", []string{"orgpolicy.policy.set"}, "SetOrgPolicyConstraints"},
		{"CreateGCEInstanceWithSA", []string{"iam.serviceAccounts.actAs", "compute.instances.create"}, "ActAsDeployCompute"},
		{"ExfilCloudFunctionCredsAuthCall", []string{"iam.serviceAccounts.actAs", "cloudfunctions.functions.create"}, "ActAsDeployFunction"},
		{"ExfilCloudRunServiceAuthCall", []string{"iam.serviceAccounts.actAs", "run.services.create"}, "ActAsDeployCloudRun"},
		{"UpdateCloudFunction", []string{"iam.serviceAccounts.actAs", "cloudfunctions.functions.update", "cloudfunctions.functions.sourceCodeSet"}, "UpdateCloudFunction"},
		{"CreateCloudSchedulerHTTPRequest", []string{"iam.serviceAccounts.actAs", "cloudscheduler.jobs.create"}, "CloudSchedulerActAs"},
	}

	for _, c := range cases {
		t.Run(c.rhino, func(t *testing.T) {
			const member = "user:dev@acme.com"
			inv := Build(RawGCP{
				ProjectID: "p1",
				Bindings:  []RawGCPBinding{{Role: "roles/custom.t", Members: []string{member}}},
				RoleDefs:  map[string][]string{"roles/custom.t": c.perms},
			})
			pe := gcpPrivescFor(inv, member)
			if pe == nil {
				t.Fatalf("%s: no privesc edge from the ingest for %v — the technique is in the "+
					"catalogue and the bench credits it, but a customer's project produces nothing",
					c.rhino, c.perms)
			}
			if pe.Target != cloudgraph.AdminID {
				t.Errorf("%s: the edge must reach admin, got target %q", c.rhino, pe.Target)
			}
			if !strings.Contains(pe.Detail, c.wantTech) {
				t.Errorf("%s: want %s named on the edge, got %q", c.rhino, c.wantTech, pe.Detail)
			}
			// A definitely-granted permission is a DEFINITE escalation. If this came back
			// condition-gated, the product would be softening a claim the evidence supports —
			// and the bench, which has no condition notion at all, could not tell.
			if pe.Condition != "" {
				t.Errorf("%s: an unconditional role grant must yield a definite edge, got %q",
					c.rhino, pe.Condition)
			}
		})
	}
}
