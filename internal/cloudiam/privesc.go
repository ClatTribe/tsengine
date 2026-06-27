package cloudiam

// Known AWS IAM privilege-escalation techniques (PMapper / Rhino "AWS IAM
// Privilege Escalation" set). Each technique is a set of permissions that,
// together, let a principal escalate to higher privilege. If a principal's
// effective permissions cover all of a technique's RequiredAny-on-each-line,
// it can escalate → a `privesc` edge in the graph.
//
// This is detection logic, not a detector we ship blind: it's the documented,
// finite set of IAM privesc primitives, mapped to a graph edge (CLAUDE.md §13 —
// orchestration/derivation logic, not a new in-house scanner).

// Technique is one privesc method: every group in All must be satisfied (the
// principal can do at least one action in each group).
type Technique struct {
	Name string
	All  [][]string // AND of (OR of actions)
}

// Techniques is the catalog. Resources are evaluated as "*" here (escalation is
// about possessing the permission); the ingest may refine per-resource.
var Techniques = []Technique{
	{Name: "CreateNewPolicyVersion", All: [][]string{{"iam:CreatePolicyVersion"}}},
	{Name: "SetExistingDefaultPolicyVersion", All: [][]string{{"iam:SetDefaultPolicyVersion"}}},
	{Name: "CreateAccessKey", All: [][]string{{"iam:CreateAccessKey"}}},
	{Name: "CreateLoginProfile", All: [][]string{{"iam:CreateLoginProfile"}}},
	{Name: "UpdateLoginProfile", All: [][]string{{"iam:UpdateLoginProfile"}}},
	{Name: "AttachUserPolicy", All: [][]string{{"iam:AttachUserPolicy"}}},
	{Name: "AttachGroupPolicy", All: [][]string{{"iam:AttachGroupPolicy"}}},
	{Name: "AttachRolePolicy", All: [][]string{{"iam:AttachRolePolicy", "sts:AssumeRole"}}},
	{Name: "PutUserPolicy", All: [][]string{{"iam:PutUserPolicy"}}},
	{Name: "PutGroupPolicy", All: [][]string{{"iam:PutGroupPolicy"}}},
	{Name: "PutRolePolicy", All: [][]string{{"iam:PutRolePolicy", "sts:AssumeRole"}}},
	{Name: "AddUserToGroup", All: [][]string{{"iam:AddUserToGroup"}}},
	{Name: "PassRoleToNewLambda", All: [][]string{{"iam:PassRole"}, {"lambda:CreateFunction"}, {"lambda:InvokeFunction"}}},
	{Name: "PassRoleToNewEC2", All: [][]string{{"iam:PassRole"}, {"ec2:RunInstances"}}},
	{Name: "PassRoleToCloudFormation", All: [][]string{{"iam:PassRole"}, {"cloudformation:CreateStack"}}},
	{Name: "UpdateLambdaCode", All: [][]string{{"lambda:UpdateFunctionCode"}}},
	{Name: "UpdateAssumeRolePolicy", All: [][]string{{"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"}}},
	// Pass-role-to-new-resource techniques on the lesser-known services PMapper/Rhino cover but the
	// catalog omitted — depth the IAM attack-path engine needs so a privesc via Glue / Data Pipeline /
	// SageMaker isn't a blind spot (each is a real, published escalation primitive).
	{Name: "PassRoleToNewGlueDevEndpoint", All: [][]string{{"iam:PassRole"}, {"glue:CreateDevEndpoint"}, {"glue:GetDevEndpoint"}}},
	{Name: "UpdateExistingGlueDevEndpoint", All: [][]string{{"glue:UpdateDevEndpoint"}}},
	{Name: "PassRoleToNewDataPipeline", All: [][]string{{"iam:PassRole"}, {"datapipeline:CreatePipeline"}, {"datapipeline:PutPipelineDefinition"}}},
	{Name: "PassRoleToNewSageMakerNotebook", All: [][]string{{"iam:PassRole"}, {"sagemaker:CreateNotebookInstance"}, {"sagemaker:CreatePresignedNotebookInstanceUrl"}}},
}

// CanDo reports whether the principal (its combined policy docs) is permitted an
// action on "*" resources.
func CanDo(action string, docs ...*Document) bool {
	ok, _ := Allows(action, "*", docs...)
	return ok
}

// DetectPrivesc returns the privesc techniques a principal's effective
// permissions enable. `can` answers whether an action is permitted — typically
// `func(a string) bool { return CanDo(a, docs...) }` so callers can inject a
// per-resource-aware evaluator if they have one.
func DetectPrivesc(can func(action string) bool) []Technique {
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
		for _, a := range group {
			if can(a) {
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
