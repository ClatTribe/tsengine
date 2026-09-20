package cloudiam

import "testing"

// The three escalation primitives CloudGoat named and this catalogue did not contain.
//
// Each is pinned in BOTH directions, because only the negative half gives the requirement list
// any meaning: a technique that fires on its most common action alone would "detect" CloudGoat
// and every ordinary operator alongside it. `ecs:RegisterTaskDefinition` is held by anyone who
// deploys a container, `glue:CreateJob` by anyone who writes an ETL job, and
// `ec2:ModifyInstanceAttribute` by most infrastructure roles in existence — it is the
// COMBINATION that is the escalation.
func TestDetectPrivesc_CloudGoatNamedPrimitives(t *testing.T) {
	fires := func(perms []string, want string) bool {
		set := map[string]bool{}
		for _, p := range perms {
			set[p] = true
		}
		for _, tech := range DetectPrivesc(func(a string) bool { return set[a] }) {
			if tech.Name == want {
				return true
			}
		}
		return false
	}

	present := map[string][]string{
		// ecs_privesc_evade_protection: register a definition naming a privileged task role,
		// then run it. The task comes up as that role.
		"PassRoleToNewECSTask": {"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"},
		// glue_privesc: the Glue ADMIN user holds exactly this set.
		"PassRoleToNewGlueJob": {"iam:PassRole", "glue:CreateJob", "glue:StartJobRun"},
		// The same scenario's user can also rewrite an existing job, which needs no PassRole
		// because the job already carries its role.
		"UpdateExistingGlueJob": {"glue:UpdateJob", "glue:StartJobRun"},
		// iam_privesc_by_ec2: the pivot role's three actions, rewriting user data on an
		// instance whose profile is AdministratorAccess.
		"EC2UserDataModification": {"ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances"},
	}
	for want, perms := range present {
		if !fires(perms, want) {
			t.Errorf("%s must fire for %v — this is the permission set CloudGoat grants", want, perms)
		}
	}

	// Each technique's SECOND action is a real alternative, not decoration: a Glue trigger
	// starts a job as surely as StartJobRun does, and ecs:StartTask places a task as RunTask
	// does. Pinned so the OR groups are not quietly narrowed to a single spelling.
	alternates := map[string][]string{
		"PassRoleToNewECSTask":  {"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:StartTask"},
		"PassRoleToNewGlueJob":  {"iam:PassRole", "glue:CreateJob", "glue:CreateTrigger"},
		"UpdateExistingGlueJob": {"glue:UpdateJob", "glue:CreateTrigger"},
	}
	for want, perms := range alternates {
		if !fires(perms, want) {
			t.Errorf("%s must fire for the alternative execution action in %v", want, perms)
		}
	}

	// THE HALF THAT COSTS SOMETHING. An incomplete set must NOT fire — each of these is a
	// permission an ordinary role holds, and a catalogue that escalated on any one of them
	// would report a privesc edge for most principals in a real account.
	absent := []struct {
		name  string
		tech  string
		perms []string
		why   string
	}{
		{"register-without-run", "PassRoleToNewECSTask", []string{"iam:PassRole", "ecs:RegisterTaskDefinition"},
			"a definition nobody can run escalates nothing"},
		{"run-without-passrole", "PassRoleToNewECSTask", []string{"ecs:RegisterTaskDefinition", "ecs:RunTask"},
			"without PassRole the task can only carry a role you already have"},
		{"create-job-without-passrole", "PassRoleToNewGlueJob", []string{"glue:CreateJob", "glue:StartJobRun"},
			"a job you cannot give a role to runs as nothing new"},
		{"update-job-without-start", "UpdateExistingGlueJob", []string{"glue:UpdateJob"},
			"rewriting a script nobody can run is not an escalation"},
		{"modify-without-stop", "EC2UserDataModification", []string{"ec2:ModifyInstanceAttribute", "ec2:StartInstances"},
			"AWS refuses a userData change while the instance runs, so the path cannot be walked"},
		{"stop-start-without-modify", "EC2UserDataModification", []string{"ec2:StopInstances", "ec2:StartInstances"},
			"rebooting an instance is not code execution on it"},
	}
	for _, c := range absent {
		if fires(c.perms, c.tech) {
			t.Errorf("%s: %s must NOT fire for %v — %s", c.name, c.tech, c.perms, c.why)
		}
	}
}

// The existing Glue DEV ENDPOINT techniques and the new Glue JOB ones are DISTINCT paths, not two
// names for one. A principal holding only the job permissions must not be credited with the dev
// endpoint method (and the reverse), or the catalogue would double-count one escalation and a
// reader could not tell which door is actually open.
func TestDetectPrivesc_GlueJobAndDevEndpointAreDistinct(t *testing.T) {
	jobOnly := map[string]bool{"iam:PassRole": true, "glue:CreateJob": true, "glue:StartJobRun": true}
	for _, tech := range DetectPrivesc(func(a string) bool { return jobOnly[a] }) {
		if tech.Name == "PassRoleToNewGlueDevEndpoint" || tech.Name == "UpdateExistingGlueDevEndpoint" {
			t.Errorf("%q fired on job-only permissions — the dev endpoint path needs glue:CreateDevEndpoint/UpdateDevEndpoint", tech.Name)
		}
	}
	devOnly := map[string]bool{"glue:UpdateDevEndpoint": true}
	for _, tech := range DetectPrivesc(func(a string) bool { return devOnly[a] }) {
		if tech.Name == "UpdateExistingGlueJob" {
			t.Error("UpdateExistingGlueJob fired on a dev-endpoint permission")
		}
	}
}
