package gcpiam

import "testing"

// IN-HOUSE FP GUARD, and labelled as such deliberately.
//
// The AWS catalogue has BishopFox's tool-testing control set — five policies an external
// party says must NOT be flagged. GCP has no published equivalent, so after adding eight
// techniques to close a measured recall gap there is no neutral way to check the cost.
// This is the weaker substitute: realistic benign permission sets that must fire nothing.
//
// It is a guard against the obvious regression, NOT evidence of specificity. The GCP
// recall number is therefore one-sided in a way the AWS pair is not, and SCOREBOARD says so.
func TestDetectPrivesc_BenignPermissionSetsFireNothing(t *testing.T) {
	for name, perms := range map[string][]string{
		"read-only viewer-ish": {
			"storage.objects.get", "storage.objects.list", "storage.buckets.get",
			"compute.instances.list", "compute.instances.get",
			"logging.logEntries.list", "monitoring.timeSeries.list",
			"resourcemanager.projects.get",
		},
		"developer without actAs": {
			"cloudfunctions.functions.get", "cloudfunctions.functions.list",
			"run.services.get", "run.services.list",
			"compute.instances.get", "storage.objects.create",
		},
		"iam reader": {
			"iam.roles.get", "iam.roles.list",
			"iam.serviceAccounts.get", "iam.serviceAccounts.list",
			"resourcemanager.projects.getIamPolicy",
		},
	} {
		granted := map[string]bool{}
		for _, p := range perms {
			granted[p] = true
		}
		got := DetectPrivesc(func(p string) bool { return granted[p] })
		if len(got) != 0 {
			names := make([]string, 0, len(got))
			for _, tch := range got {
				names = append(names, tch.Name)
			}
			t.Errorf("%s must escalate nothing, got %v", name, names)
		}
	}
}

// The actAs-gated deploy techniques must NOT fire on the deploy permission alone. Deploying
// a workload that runs as YOUR OWN identity is not escalation; it is the actAs onto a more
// privileged account that makes it one.
func TestDetectPrivesc_DeployWithoutActAsIsNotEscalation(t *testing.T) {
	for _, deploy := range []string{
		"compute.instances.create", "cloudfunctions.functions.create",
		"run.services.create", "cloudscheduler.jobs.create",
		"cloudfunctions.functions.update", "cloudfunctions.functions.sourceCodeSet",
	} {
		granted := map[string]bool{deploy: true}
		for _, tch := range DetectPrivesc(func(p string) bool { return granted[p] }) {
			t.Errorf("%s alone fired %q — without actAs the workload runs as the caller's own "+
				"identity, which escalates nothing", deploy, tch.Name)
		}
	}
}

// Every technique carrying a precondition must SAY it. A technique that fires on a
// permission whose exploitability depends on something we cannot see, without stating the
// dependency, is claiming more than it proved.
func TestTechniques_PreconditionedOnesCarryANote(t *testing.T) {
	needNote := map[string]bool{
		"SetServiceAccountIamPolicy": true, "DeploymentManagerPrivesc": true,
		"UpdateCloudFunction": true, "CreateServiceAccountHMACKey": true,
		"CreateAPIKey": true, "ViewExistingAPIKeys": true, "SetOrgPolicyConstraints": true,
	}
	seen := map[string]bool{}
	for _, tch := range Techniques {
		seen[tch.Name] = true
		if needNote[tch.Name] && tch.Note == "" {
			t.Errorf("%q depends on something the permissions do not establish and must state it in Note", tch.Name)
		}
	}
	for n := range needNote {
		if !seen[n] {
			t.Errorf("expected technique %q to exist", n)
		}
	}
}
