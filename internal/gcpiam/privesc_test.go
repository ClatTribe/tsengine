package gcpiam

import "testing"

func TestDetectPrivesc_GCP(t *testing.T) {
	fire := func(perms ...string) map[string]bool {
		m := map[string]bool{}
		for _, p := range perms {
			m[p] = true
		}
		return m
	}
	cases := map[string][]string{
		"SetIamPolicy":                 {"resourcemanager.projects.setIamPolicy"},
		"ServiceAccountKeyCreate":      {"iam.serviceAccountKeys.create"},
		"ServiceAccountGetAccessToken": {"iam.serviceAccounts.getAccessToken"},
		"ServiceAccountSignBlobOrJwt":  {"iam.serviceAccounts.signJwt"},
		"UpdateCustomRole":             {"iam.roles.update"},
		"ActAsDeployCompute":           {"iam.serviceAccounts.actAs", "compute.instances.create"},
		"ActAsDeployCloudRun":          {"iam.serviceAccounts.actAs", "run.services.create"},
		"CloudBuildPrivesc":            {"cloudbuild.builds.create"},
	}
	for want, perms := range cases {
		set := fire(perms...)
		got := false
		for _, tech := range DetectPrivesc(func(p string) bool { return set[p] }) {
			if tech.Name == want {
				got = true
			}
		}
		if !got {
			t.Errorf("expected GCP privesc technique %q for perms %v", want, perms)
		}
	}
	// actAs alone (no deploy permission) must NOT trip any deploy technique (the AND contract — no false edge).
	only := fire("iam.serviceAccounts.actAs")
	for _, tech := range DetectPrivesc(func(p string) bool { return only[p] }) {
		t.Errorf("iam.serviceAccounts.actAs alone must not trip %q (needs a deploy permission)", tech.Name)
	}
	// a read-only principal escalates to nothing.
	if got := DetectPrivesc(func(string) bool { return false }); len(got) != 0 {
		t.Errorf("a principal with no privesc perms must yield zero techniques, got %v", got)
	}
}
