package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tfPolicy = `
resource "aws_iam_policy" "privesc10-PutUserPolicy" {
  name = "privesc10-PutUserPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "iam:PutUserPolicy"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "privesc10-role" {
  name = "r"
  assume_role_policy = jsonencode({
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow" }]
  })
}
`

// The trust policy in the same file must NOT be read as a granted permission — an
// assume_role_policy says who may assume the role, not what the role can do. Counting it
// would credit us with detecting an escalation the corpus never granted.
func TestExtractActions_ReadsThePolicyAndNotTheTrustPolicy(t *testing.T) {
	got := ExtractActions(tfPolicy)
	if len(got) != 1 || got[0] != "iam:PutUserPolicy" {
		t.Fatalf("want only the aws_iam_policy actions, got %v", got)
	}
}

func TestExtractActions_HandlesActionLists(t *testing.T) {
	tf := `resource "aws_iam_policy" "x" {
  policy = jsonencode({
    Statement = [
      {
        Action = ["glue:CreateDevEndpoint", "iam:PassRole"]
        Effect = "Allow"
      },
    ]
  })
}`
	got := ExtractActions(tf)
	if len(got) != 2 || got[0] != "glue:CreateDevEndpoint" || got[1] != "iam:PassRole" {
		t.Fatalf("list-form actions must all be read, sorted: %v", got)
	}
}

// A file declaring no policy is not a parse failure — many corpus files are role-only.
func TestExtractActions_NoPolicyIsNotAnError(t *testing.T) {
	if got := ExtractActions(`resource "aws_iam_user" "u" { name = "u" }`); len(got) != 0 {
		t.Fatalf("a file with no policy grants nothing, got %v", got)
	}
}

// THE SHAPE GUARD. This reads ONE corpus in ONE known shape. If the corpus changes, the
// count must drop VISIBLY rather than the score quietly improving on fewer cases — which
// is precisely how a benchmark stops measuring anything.
func TestScoreIAMVulnerable_ShapeChangeIsVisibleNotSilent(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("privesc1-Good.tf", tfPolicy)
	// A shape we do not parse: the extractor must find nothing rather than guess.
	write("privesc2-Unparseable.tf", `resource "aws_iam_policy" "x" { policy = file("elsewhere.json") }`)
	// Not a privesc path at all.
	write("variables.tf", tfPolicy)

	res, err := ScoreIAMVulnerable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 {
		t.Fatalf("only the parseable privesc file should be scored, got %d", res.Total)
	}
	if res.Paths[0].Name != "privesc1-Good" {
		t.Fatalf("the corpus file name is the answer key: %+v", res.Paths[0])
	}
	if !res.Paths[0].Found {
		t.Fatal("iam:PutUserPolicy is a known escalation and must be detected")
	}
}

// The file NAME is the answer, never an input. A file named after a technique whose
// actions are harmless must NOT score as detected, or the benchmark grades itself.
func TestScoreIAMVulnerable_NameIsNeverAnInput(t *testing.T) {
	dir := t.TempDir()
	body := `resource "aws_iam_policy" "x" {
  policy = jsonencode({
    Statement = [{ Action = "s3:GetObject", Effect = "Allow" }]
  })
}`
	if err := os.WriteFile(filepath.Join(dir, "privesc1-CreateNewPolicyVersion.tf"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ := ScoreIAMVulnerable(dir)
	if res.Hits != 0 {
		t.Fatal("a file named after an escalation whose policy only reads objects must not score — " +
			"otherwise the benchmark is grading the file name")
	}
}

func TestRenderIAMVulnerable_NamesTheMissesAndTheirActions(t *testing.T) {
	r := IAMVulnResult{
		Total: 2, Hits: 1,
		Paths: []IAMVulnPath{
			{Name: "privesc1-Good", Actions: []string{"iam:CreatePolicyVersion"}, Detected: []string{"CreateNewPolicyVersion"}, Found: true},
			{Name: "privesc-ssmSendCommand", Actions: []string{"ssm:sendCommand"}},
		},
	}
	out := RenderIAMVulnerable(r)
	if !strings.Contains(out, "privesc-ssmSendCommand") || !strings.Contains(out, "ssm:sendCommand") {
		t.Fatal("a miss must name the path AND what it granted, or nobody can judge whether it is a gap")
	}
	if !strings.Contains(out, "Bishop Fox") {
		t.Fatal("the report must say whose answer key this is — that is the entire claim")
	}
}
