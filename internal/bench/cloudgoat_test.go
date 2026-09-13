package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeScenario lays out one scenario in CloudGoat's own shape: <name>/README.md and
// <name>/terraform/*.tf, plus optional <name>/terraform/policies/*.json.
func writeScenario(t *testing.T, root, name, readme string, tf map[string]string, policies map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name, "terraform")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if readme != "" {
		if err := os.WriteFile(filepath.Join(root, name, "README.md"), []byte(readme), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for fn, body := range tf {
		if err := os.WriteFile(filepath.Join(dir, fn), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(policies) > 0 {
		pdir := filepath.Join(dir, "policies")
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		for fn, body := range policies {
			if err := os.WriteFile(filepath.Join(pdir, fn), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A synthetic corpus in CloudGoat's own layout, exercising every judgement the scorer makes:
// an HCL jsonencode policy carrying a real escalation; a file-based policies/ directory where one
// version is ADMIN (must not be credited) and another carries a genuine escalation; a
// non-decidable SSRF scenario whose policy grants nothing dangerous; and a trust policy on
// aws_iam_role that must be IGNORED even though it says sts:AssumeRole.
func TestScoreCloudGoat_ScoresDecidableScenariosOnlyAndNeverCreditsAdmin(t *testing.T) {
	root := t.TempDir()

	// 1. A named privesc scenario with an inline HCL policy granting a real escalation.
	writeScenario(t, root, "iam_privesc_by_versions",
		"# Scenario\n\n## Summary\n\nStarting as user chris, escalate privileges via policy versions.\n",
		map[string]string{"iam.tf": `
resource "aws_iam_policy" "chris" {
  name = "cg-chris"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["iam:CreatePolicyVersion", "iam:ListPolicyVersions"]
      Resource = "*"
    }]
  })
}
`}, nil)

	// 2. A privesc scenario whose policies live in files: v1 is ADMIN (never credited), v2 is a real
	//    escalation. Also carries a ROLE trust policy that says sts:AssumeRole and must be ignored.
	writeScenario(t, root, "iam_privesc_by_rollback",
		"# Scenario\n\n## Summary\n\nEscalate privileges by rolling back a policy version.\n",
		map[string]string{"iam.tf": `
resource "aws_iam_policy" "versioned" {
  name   = "cg-raynor"
  policy = file("policies/v1.json")
}

resource "aws_iam_role" "runner" {
  name = "cg-runner"
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}
`},
		map[string]string{
			"v1.json": `{"Version":"2012-10-17","Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}]}`,
			"v2.json": `{"Version":"2012-10-17","Statement":[{"Action":["iam:SetDefaultPolicyVersion"],"Effect":"Allow","Resource":"*"}]}`,
		})

	// 3. A scenario Rhino documents as an application/SSRF route, with a harmless policy.
	writeScenario(t, root, "cloud_breach_s3",
		"# Scenario\n\n## Summary\n\nExploit a misconfigured reverse proxy to query the metadata service.\n",
		map[string]string{"iam.tf": `
resource "aws_iam_policy" "ro" {
  name = "cg-ro"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject", "ec2:DescribeInstances"], Resource = "*" }]
  })
}
`}, nil)

	res, err := ScoreCloudGoat(root)
	if err != nil {
		t.Fatal(err)
	}

	if res.Total != 3 {
		t.Fatalf("want 3 scenarios with terraform, got %d", res.Total)
	}
	if res.Decidable != 2 {
		t.Fatalf("only the two privesc-named scenarios are IAM-decidable, got %d", res.Decidable)
	}
	if res.Hits != 2 || res.Recall() != 1.0 {
		t.Errorf("both decidable scenarios grant a real escalation: hits=%d recall=%.2f", res.Hits, res.Recall())
	}

	by := map[string]CloudGoatScenario{}
	for _, s := range res.Scenarios {
		by[s.Name] = s
	}

	// The admin document is COUNTED and never credited — a policy granting "*" is the destination,
	// not a path to it. Crediting it would score us for "finding" an escalation in a document that
	// simply IS admin.
	rb := by["iam_privesc_by_rollback"]
	if rb.WildcardDocs != 1 {
		t.Errorf("the admin (Action:*) version must be counted as a wildcard doc, got %d", rb.WildcardDocs)
	}
	if !rb.Found || !contains(rb.Detected, "SetExistingDefaultPolicyVersion") {
		t.Errorf("the non-admin version grants a real escalation and must be detected, got %v", rb.Detected)
	}
	// The role's TRUST policy says sts:AssumeRole; extracting it would manufacture an escalation
	// from a document that only says who may assume the role.
	for _, d := range rb.Detected {
		if strings.Contains(strings.ToLower(d), "assumerole") {
			t.Errorf("a trust policy was scored as an identity policy: %v", rb.Detected)
		}
	}

	// The application-route scenario is neither decidable nor found — a miss there would be a
	// correct refusal, so it must not enter the denominator at all.
	s3 := by["cloud_breach_s3"]
	if s3.IAMDecidable {
		t.Error("an SSRF/application scenario is not IAM-decidable")
	}
	if s3.Found {
		t.Errorf("a read-only policy must not yield an escalation, got %v", s3.Detected)
	}
}

// The render names the misses and, crucially, the scenarios the number EXCLUDES — a recall over a
// subset is only honest when the reader can see the subset's complement.
func TestRenderCloudGoat_ShowsTheSubsetAndItsComplement(t *testing.T) {
	root := t.TempDir()
	writeScenario(t, root, "lambda_privesc", "# S\n\n## Summary\n\nEscalate via lambda.\n",
		map[string]string{"iam.tf": `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], Resource = "*" }] })
}
`}, nil)
	writeScenario(t, root, "rce_web_app", "# S\n\n## Summary\n\nRemote code execution on a vulnerable web app.\n",
		map[string]string{"iam.tf": `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }] })
}
`}, nil)

	res, err := ScoreCloudGoat(root)
	if err != nil {
		t.Fatal(err)
	}
	out := RenderCloudGoat(res)

	if !strings.Contains(out, "EXTERNAL answer key") {
		t.Error("the report must say the key is external — that is the whole point of it")
	}
	if !strings.Contains(out, "POLICY-ONLY") {
		t.Error("the report must state that it cannot see application/network routes")
	}
	if !strings.Contains(out, "lambda_privesc") {
		t.Error("the decidable scenario is missing from the report")
	}
	// The excluded scenario must be listed WITH Rhino's route, not silently dropped.
	if !strings.Contains(out, "rce_web_app") || !strings.Contains(out, "Remote code execution") {
		t.Error("a non-decidable scenario must be listed with the route Rhino documents, so the " +
			"number's scope is visible rather than implied")
	}
}

// A directory with no scenarios is an ERROR-shaped result, not a perfect score: recall over an
// empty denominator must be 0, never 1 (the vacuous-pass shape §14.2 rule 5 names).
func TestScoreCloudGoat_EmptyCorpusIsNotAPerfectScore(t *testing.T) {
	res, err := ScoreCloudGoat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 0 || res.Decidable != 0 {
		t.Fatalf("an empty corpus scores nothing, got %+v", res)
	}
	if res.Recall() != 0 {
		t.Errorf("recall over an empty corpus must be 0, not %.2f — a rate that rises as the "+
			"evidence disappears is the vacuous pass", res.Recall())
	}
}

func contains(hay []string, want string) bool {
	for _, h := range hay {
		if h == want {
			return true
		}
	}
	return false
}

// The extractor must read IDENTITY policies only. aws_iam_role's inline document is the TRUST
// policy — it says WHO MAY ASSUME the role, not what the role may do — so mining it for granted
// actions manufactures an escalation out of a document that grants the principal nothing.
//
// Tested at the extractor rather than through a scenario, because a realistic trust policy contains
// only sts:AssumeRole, which yields no technique either way: a scenario-level assertion passes
// whether or not the guard exists. This fixture gives the role a trust document carrying actions
// that WOULD produce techniques if misread, so the guard is actually exercised.
func TestExtractPolicyDocs_IgnoresRoleTrustPolicies(t *testing.T) {
	tf := `
resource "aws_iam_policy" "identity" {
  name   = "real-identity-policy"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }] })
}

resource "aws_iam_role" "runner" {
  name = "cg-runner"
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = ["sts:AssumeRole", "iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`
	docs := ExtractPolicyDocs(tf)
	if len(docs) != 1 {
		t.Fatalf("exactly one IDENTITY policy should be extracted, got %d: %q", len(docs), docs)
	}
	if !strings.Contains(docs[0], "s3:GetObject") {
		t.Errorf("the extracted document is not the identity policy: %q", docs[0])
	}
	for _, d := range docs {
		if strings.Contains(d, "lambda:CreateFunction") || strings.Contains(d, "assume_role_policy") {
			t.Errorf("a role TRUST policy was extracted as an identity policy — its actions would be "+
				"credited as granted permissions and manufacture an escalation: %q", d)
		}
	}

	// And the actions of that trust policy must not reach the detector.
	var all []string
	for _, d := range docs {
		all = append(all, actionsIn(d)...)
	}
	for _, a := range all {
		if strings.EqualFold(a, "iam:PassRole") || strings.EqualFold(a, "lambda:CreateFunction") {
			t.Errorf("trust-policy action %q leaked into the granted set", a)
		}
	}
}

// EVERY adjacent identity policy is extracted — the bug the split replaced silently dropped every
// other one. The original pattern ended with a CONSUMED delimiter (`(?:\nresource\s+"|…)`, since
// RE2 has no lookahead), so the next block's header was eaten and could not start a match: three
// adjacent aws_iam_policy resources yielded two.
//
// It mattered because the bias runs ONE WAY. A dropped document is an escalation nobody looked at,
// so the recall it produces is too LOW — the instrument understated us, and a number published from
// it would have been wrong in the direction nobody double-checks.
func TestExtractPolicyDocs_ExtractsEveryAdjacentPolicy(t *testing.T) {
	tf := `
resource "aws_iam_policy" "a" {
  policy = jsonencode({ Statement = [{ Action = ["iam:PassRole"] }] })
}

resource "aws_iam_policy" "b" {
  policy = jsonencode({ Statement = [{ Action = ["lambda:CreateFunction"] }] })
}

resource "aws_iam_policy" "c" {
  policy = jsonencode({ Statement = [{ Action = ["s3:GetObject"] }] })
}
`
	docs := ExtractPolicyDocs(tf)
	if len(docs) != 3 {
		t.Fatalf("every adjacent identity policy must be extracted, got %d of 3 — a dropped document "+
			"is an unseen escalation, which understates recall: %q", len(docs), docs)
	}
	want := []string{"iam:PassRole", "lambda:CreateFunction", "s3:GetObject"}
	for i, w := range want {
		if !strings.Contains(docs[i], w) {
			t.Errorf("doc %d should carry %s, got %q", i, w, docs[i])
		}
	}
}

// A block that is NOT an identity policy is skipped WITHOUT swallowing the block after it — the
// same consumption trap, from the other side: a data/module/role block between two policies must
// not hide the second one.
func TestExtractPolicyDocs_NonPolicyBlockDoesNotHideTheNextPolicy(t *testing.T) {
	tf := `
resource "aws_iam_role" "runner" {
  assume_role_policy = jsonencode({ Statement = [{ Action = ["sts:AssumeRole", "iam:PassRole"] }] })
}

resource "aws_iam_policy" "real" {
  policy = jsonencode({ Statement = [{ Action = ["iam:CreateAccessKey"] }] })
}
`
	docs := ExtractPolicyDocs(tf)
	if len(docs) != 1 {
		t.Fatalf("exactly the one identity policy should be extracted, got %d: %q", len(docs), docs)
	}
	if !strings.Contains(docs[0], "iam:CreateAccessKey") {
		t.Errorf("the policy following a role block was not extracted: %q", docs[0])
	}
	if strings.Contains(docs[0], "sts:AssumeRole") {
		t.Error("the role TRUST policy leaked into the extracted identity policy")
	}
}
