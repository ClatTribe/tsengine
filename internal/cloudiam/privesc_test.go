package cloudiam

import "testing"

// The lesser-known pass-role privesc techniques (Glue / Data Pipeline / SageMaker) must be detected when a
// principal holds the required permission set — the depth additions (Rhino/PMapper) that close the IAM blind spot.
func TestDetectPrivesc_GlueDataPipelineSageMaker(t *testing.T) {
	cases := map[string][]string{
		"PassRoleToNewGlueDevEndpoint":   {"iam:PassRole", "glue:CreateDevEndpoint", "glue:GetDevEndpoint"},
		"UpdateExistingGlueDevEndpoint":  {"glue:UpdateDevEndpoint"},
		"PassRoleToNewDataPipeline":      {"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"},
		"PassRoleToNewSageMakerNotebook": {"iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"},
	}
	for want, perms := range cases {
		set := map[string]bool{}
		for _, p := range perms {
			set[p] = true
		}
		got := false
		for _, tech := range DetectPrivesc(func(a string) bool { return set[a] }) {
			if tech.Name == want {
				got = true
			}
		}
		if !got {
			t.Errorf("expected privesc technique %q to fire for perms %v", want, perms)
		}
	}
	// A principal with only iam:PassRole (and nothing else) must NOT trip any of the new multi-perm techniques.
	only := map[string]bool{"iam:PassRole": true}
	for _, tech := range DetectPrivesc(func(a string) bool { return only[a] }) {
		switch tech.Name {
		case "PassRoleToNewGlueDevEndpoint", "PassRoleToNewDataPipeline", "PassRoleToNewSageMakerNotebook":
			t.Errorf("%q must not fire with iam:PassRole alone (needs the service create perms)", tech.Name)
		}
	}
}
