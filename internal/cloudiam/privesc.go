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
	// Note states a PRECONDITION the permissions alone cannot establish — most often
	// "you must be able to use the role you just gave privilege to". It exists because
	// the alternative was silently folding that precondition INTO All, which under-reports:
	// a principal that can attach AdministratorAccess to a role is a real escalation
	// primitive whether or not it can also sts:AssumeRole today, and Rhino's and Bishop
	// Fox's catalogues both treat the write alone as the path. Stating the caveat lets a
	// reader judge it; hiding it in the requirement list let us disagree with the
	// published research without anyone noticing.
	Note string `json:"note,omitempty"`
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
	{Name: "AttachRolePolicy", All: [][]string{{"iam:AttachRolePolicy"}},
		Note: "requires being able to use the role afterwards (assume it, or reach a service that runs as it)"},
	{Name: "PutUserPolicy", All: [][]string{{"iam:PutUserPolicy"}}},
	{Name: "PutGroupPolicy", All: [][]string{{"iam:PutGroupPolicy"}}},
	{Name: "PutRolePolicy", All: [][]string{{"iam:PutRolePolicy"}},
		Note: "requires being able to use the role afterwards (assume it, or reach a service that runs as it)"},
	{Name: "AddUserToGroup", All: [][]string{{"iam:AddUserToGroup"}}},
	{Name: "PassRoleToNewLambda", All: [][]string{{"iam:PassRole"}, {"lambda:CreateFunction"}, {"lambda:InvokeFunction"}}},
	{Name: "PassRoleToNewEC2", All: [][]string{{"iam:PassRole"}, {"ec2:RunInstances"}}},
	{Name: "PassRoleToCloudFormation", All: [][]string{{"iam:PassRole"}, {"cloudformation:CreateStack"}}},
	{Name: "UpdateLambdaCode", All: [][]string{{"lambda:UpdateFunctionCode"}}},
	{Name: "UpdateAssumeRolePolicy", All: [][]string{{"iam:UpdateAssumeRolePolicy"}, {"sts:AssumeRole"}}},
	// Pass-role-to-new-resource techniques on the lesser-known services PMapper/Rhino cover but the
	// catalog omitted — depth the IAM attack-path engine needs so a privesc via Glue / Data Pipeline /
	// SageMaker isn't a blind spot (each is a real, published escalation primitive).
	{Name: "PassRoleToNewGlueDevEndpoint", All: [][]string{{"iam:PassRole"}, {"glue:CreateDevEndpoint"}, {"glue:GetDevEndpoint"}}},
	{Name: "UpdateExistingGlueDevEndpoint", All: [][]string{{"glue:UpdateDevEndpoint"}}},
	{Name: "PassRoleToNewDataPipeline", All: [][]string{{"iam:PassRole"}, {"datapipeline:CreatePipeline"}, {"datapipeline:PutPipelineDefinition"}}},
	{Name: "PassRoleToNewSageMakerNotebook", All: [][]string{{"iam:PassRole"}, {"sagemaker:CreateNotebookInstance"}, {"sagemaker:CreatePresignedNotebookInstanceUrl"}}},

	// Added after the IAM-Vulnerable (BishopFox) run scored 64.5%: each of these is a
	// path that corpus names and this catalogue simply did not contain. They are not
	// tuning to a benchmark — they are published escalation primitives we were blind to,
	// and the benchmark is how we learned which.

	// Run-command-on-an-instance: the instance executes as ITS role, so anyone who can
	// send it a command inherits that role without ever touching IAM.
	{Name: "SSMSendCommand", All: [][]string{{"ssm:SendCommand"}, {"ec2:DescribeInstances"}},
		Note: "escalates to the target instance's role; requires an instance with a more privileged profile"},
	{Name: "SSMStartSession", All: [][]string{{"ssm:StartSession"}, {"ec2:DescribeInstances"}},
		Note: "escalates to the target instance's role; requires an instance with a more privileged profile"},
	// Pushing an SSH key to an instance is the same move by a different door.
	{Name: "EC2InstanceConnect", All: [][]string{
		{"ec2-instance-connect:SendSSHPublicKey", "ec2-instance-connect:SendSerialConsoleSSHPublicKey"},
		{"ec2:DescribeInstances"}},
		Note: "escalates to the target instance's role; requires network reach to the instance"},

	// Build/compute services that will run your code AS a role you pass them.
	{Name: "PassRoleToNewCodeBuildProject", All: [][]string{
		{"iam:PassRole"}, {"codebuild:CreateProject"}, {"codebuild:StartBuild", "codebuild:StartBuildBatch"}}},
	{Name: "PassRoleToSageMakerProcessingJob", All: [][]string{{"iam:PassRole"}, {"sagemaker:CreateProcessingJob"}}},
	{Name: "PassRoleToSageMakerTrainingJob", All: [][]string{{"iam:PassRole"}, {"sagemaker:CreateTrainingJob"}}},
	// A presigned URL to an EXISTING notebook needs no PassRole at all — the notebook
	// already runs as its role, and the URL is the way in.
	{Name: "SageMakerPresignedNotebookURL", All: [][]string{{"sagemaker:CreatePresignedNotebookInstanceUrl"}},
		Note: "escalates to an existing notebook's role; requires a notebook to exist"},

	// Updating a stack re-deploys it with the stack's role, which is the CreateStack
	// technique's other half and was missing.
	{Name: "UpdateCloudFormationStack", All: [][]string{{"cloudformation:UpdateStack"}},
		Note: "escalates to the existing stack's role; requires a stack with a more privileged role"},

	// A Lambda can be triggered by an event source rather than invoked directly — same
	// escalation, and the catalogue only knew the direct-invoke form.
	{Name: "PassRoleToNewLambdaThenEventSource", All: [][]string{
		{"iam:PassRole"}, {"lambda:CreateFunction"}, {"lambda:CreateEventSourceMapping"}}},
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
