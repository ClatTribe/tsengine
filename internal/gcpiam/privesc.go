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
	// Note states a PRECONDITION the permissions alone cannot establish — "a privileged
	// service account must exist to impersonate", "a key must already be there to list".
	// It exists so the caveat travels with the finding instead of being folded silently
	// into the requirement list, where it would under-report. Mirrors cloudiam.Technique.
	Note string `json:"note,omitempty"`
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

	// Added after scoring 65.2% against RhinoSecurityLabs' published catalogue — the same
	// research this file's header already cites. Each is a method that catalogue names and
	// this one did not contain.

	// Granting yourself a role ON a service account (tokenCreator, actAs) is a DIFFERENT
	// mechanism from granting yourself a role on the project, and it is the one an
	// attacker more often holds: SA-scoped bindings are handed out far more freely than
	// project-scoped ones.
	{Name: "SetServiceAccountIamPolicy", All: [][]string{{"iam.serviceAccounts.setIamPolicy"}},
		Note: "grant yourself tokenCreator/actAs on a privileged service account, then impersonate it"},

	// Deployment Manager runs deployments as the Google APIs service agent by DEFAULT, so
	// no actAs is needed — the same shape as Cloud Build. The catalogue already had the
	// actAs variant and was missing this one.
	{Name: "DeploymentManagerPrivesc", All: [][]string{{"deploymentmanager.deployments.create"}},
		Note: "deployments run as the Google APIs service agent unless overridden"},

	// UPDATING a function that already runs as a privileged SA is the create-path's other
	// half — the same create-vs-update asymmetry the AWS catalogue had with CloudFormation.
	{Name: "UpdateCloudFunction", All: [][]string{
		{"iam.serviceAccounts.actAs"},
		{"cloudfunctions.functions.update"},
		{"cloudfunctions.functions.sourceCodeSet"}},
		Note: "requires an existing function attached to a more privileged service account"},

	// Cloud Scheduler jobs run as a service account and can call any HTTP target, which
	// includes Google's own APIs.
	{Name: "CloudSchedulerActAs", All: [][]string{
		{"iam.serviceAccounts.actAs"}, {"cloudscheduler.jobs.create"}}},

	// HMAC keys are long-lived interoperability credentials FOR a service account — a
	// standing credential minted without ever touching iam.serviceAccountKeys.
	{Name: "CreateServiceAccountHMACKey", All: [][]string{{"storage.hmacKeys.create"}},
		Note: "mints long-lived interop credentials for a service account"},

	// API keys are credentials in their own right; creating one, or reading the ones that
	// already exist, is credential access rather than role escalation — which is why both
	// carry a Note rather than being presented as a role change.
	{Name: "CreateAPIKey", All: [][]string{{"serviceusage.apiKeys.create"}},
		Note: "an API key is a standing credential; scope depends on the key's restrictions"},
	{Name: "ViewExistingAPIKeys", All: [][]string{{"serviceusage.apiKeys.list"}},
		Note: "reads existing API keys; requires keys to exist, and their scope is theirs not yours"},

	// Setting org-policy constraints does not escalate BY ITSELF — it removes the guardrail
	// that was stopping another escalation (the classic being the ban on service-account
	// key creation). Rhino catalogues it as a method and so does this, with the dependency
	// stated rather than implied.
	{Name: "SetOrgPolicyConstraints", All: [][]string{{"orgpolicy.policy.set"}},
		Note: "does not escalate alone — it lifts the constraint blocking another escalation"},
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
