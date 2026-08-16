package cloudtocode

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// TestIndexDir_ReadsCloudGoatTerraform is a feasibility probe, skipped unless a CloudGoat checkout is
// present.
//
// IT ANSWERS "CAN WE READ IT" WITH YES, AND "IS THAT ENOUGH" WITH NO.
//
// The indexer parses CloudGoat's terraform fine — 15 resources across 12 types for cloud_breach_s3,
// including the aws_instance, aws_iam_role, aws_s3_bucket and both aws_security_groups that form the
// documented attack path. So the ground truth is machine-READABLE.
//
// It is not machine-DERIVABLE. The values that constitute the misconfigurations are terraform
// VARIABLES resolved at apply time — cloud_breach_s3's security group reads
// `cidr_blocks = var.cg_whitelist`, i.e. the deployer's own IP range, and other rules are multi-line
// lists this line-based indexer cannot reconstruct. Nothing static says "this SG is open to the
// internet"; that only becomes true in a deployed account.
//
// So a terraform→inventory mapper would have to INVENT the attribute values, which is authoring a
// fixture with extra steps — and a worse one, because it would look externally derived. Measuring
// the cloud asset against CloudGoat/AWSGoat/flaws.cloud for real requires deploying them into an AWS
// account: a credentials-and-cost decision, not an engineering gap.
//
// Kept as a probe so the next person does not spend the same hour discovering this.
func TestIndexDir_ReadsCloudGoatTerraform(t *testing.T) {
	dir := "/tmp/cgprobe/cloudgoat/scenarios/aws/cloud_breach_s3/terraform"
	if _, err := os.Stat(dir); err != nil {
		t.Skip("no CloudGoat checkout at " + dir)
	}
	res, err := IndexDir(dir)
	if err != nil {
		t.Fatalf("IndexDir: %v", err)
	}
	byType := map[string]int{}
	for _, r := range res {
		byType[r.Type]++
	}
	keys := make([]string, 0, len(byType))
	for k := range byType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("indexed %d resources across %d types", len(res), len(byType))
	for _, k := range keys {
		t.Logf("  %-40s %d", k, byType[k])
	}
	if len(res) == 0 {
		t.Error("indexed nothing — CloudGoat terraform is not readable by this indexer as-is")
	}
	// Pin the reason this cannot become a scoring harness: the misconfiguration values are variables.
	if b, err := os.ReadFile(dir + "/ec2.tf"); err == nil && !strings.Contains(string(b), "var.cg_whitelist") {
		t.Log("NOTE: cloud_breach_s3 no longer parameterises its ingress CIDR — re-evaluate whether a " +
			"static terraform→inventory mapping has become possible")
	}
}
