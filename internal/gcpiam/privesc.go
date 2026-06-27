package gcpiam

// Known GCP IAM privilege-escalation techniques (the Rhino Security Labs "Privilege Escalation in
// Google Cloud Platform" set + the GCP-IAM-privesc body of research). Each technique is a set of IAM
// permissions that, together, let a principal escalate to higher privilege. If a principal's effective
// permissions cover every group (one permission per group), it can escalate → a `privesc` edge in the
// graph. This is the GCP twin of internal/cloudiam.Techniques (AWS) — so multi-cloud attack-path
// reasoning is symmetric across AWS+GCP, not shallower off-AWS (CLAUDE.md §10).
//
// This is the documented, finite set of GCP IAM privesc primitives mapped to a graph edge (CLAUDE.md
// §13 — derivation logic, not a new in-house scanner).

// Technique is one privesc method: every group in All must be satisfied (the principal can do at least
// one permission in each group).
type Technique struct {
	Name string
	All  [][]string // AND of (OR of permissions)
}

// Techniques is the GCP privesc catalog. Permissions are GCP IAM permission strings
// (service.resource.verb). Resources are evaluated as project-wide here (escalation is about possessing
// the permission); a per-resource-aware evaluator can refine via the injected `can`.
var Techniques = []Technique{
	// Grant yourself (or a controlled principal) a higher role at project/folder/org scope — the single
	// most direct escalation.
	{Name: "SetIamPolicy", All: [][]string{{
		"resourcemanager.projects.setIamPolicy",
		"resourcemanager.folders.setIamPolicy",
		"resourcemanager.organizations.setIamPolicy",
	}}},
	// Mint a key for a more-privileged service account, then authenticate as it.
	{Name: "ServiceAccountKeyCreate", All: [][]string{{"iam.serviceAccountKeys.create"}}},
	// Directly mint a short-lived token for a privileged SA (impersonation).
	{Name: "ServiceAccountGetAccessToken", All: [][]string{{"iam.serviceAccounts.getAccessToken"}}},
	// Forge a signed blob / JWT as a privileged SA.
	{Name: "ServiceAccountSignBlobOrJwt", All: [][]string{{
		"iam.serviceAccounts.signBlob",
		"iam.serviceAccounts.signJwt",
	}}},
	// Mint an OIDC identity token as a privileged SA.
	{Name: "ServiceAccountGetOpenIdToken", All: [][]string{{"iam.serviceAccounts.getOpenIdToken"}}},
	// Chain impersonation across a delegation list.
	{Name: "ServiceAccountImplicitDelegation", All: [][]string{{"iam.serviceAccounts.implicitDelegation"}}},
	// Add permissions to a custom role you are already granted.
	{Name: "UpdateCustomRole", All: [][]string{{"iam.roles.update"}}},
	// Deploy a workload that RUNS AS a more-privileged SA (actAs + a deploy primitive), then ride its
	// metadata token. One technique per deploy service.
	{Name: "ActAsDeployCompute", All: [][]string{{"iam.serviceAccounts.actAs"}, {"compute.instances.create"}}},
	{Name: "ActAsDeployFunction", All: [][]string{{"iam.serviceAccounts.actAs"}, {"cloudfunctions.functions.create"}}},
	{Name: "ActAsDeployCloudRun", All: [][]string{{"iam.serviceAccounts.actAs"}, {"run.services.create"}}},
	{Name: "ActAsDeployDeploymentManager", All: [][]string{{"iam.serviceAccounts.actAs"}, {"deploymentmanager.deployments.create"}}},
	// Cloud Build runs builds as the highly-privileged Cloud Build SA by default — a build you create can
	// act on its behalf without a separate actAs.
	{Name: "CloudBuildPrivesc", All: [][]string{{"cloudbuild.builds.create"}}},
}

// DetectPrivesc returns the GCP privesc techniques a principal's effective permissions enable. `can`
// answers whether a permission is held — typically wrapping gcpiam.Authorize over the principal's
// hierarchy-inherited bindings, so callers get policy-accurate escalation detection.
func DetectPrivesc(can func(permission string) bool) []Technique {
	if can == nil {
		return nil
	}
	var out []Technique
	for _, t := range Techniques {
		if satisfies(t, can) {
			out = append(out, t)
		}
	}
	return out
}

func satisfies(t Technique, can func(string) bool) bool {
	for _, group := range t.All {
		anyOK := false
		for _, p := range group {
			if can(p) {
				anyOK = true
				break
			}
		}
		if !anyOK {
			return false
		}
	}
	return true
}
