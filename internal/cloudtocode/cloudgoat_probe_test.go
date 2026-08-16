package cloudtocode

import (
	"os"
	"sort"
	"testing"
)

// TestIndexDir_ReadsCloudGoatTerraform is a feasibility probe, skipped unless a CloudGoat checkout is
// present. It answers whether the external cloud benchmark can be consumed WITHOUT provisioning AWS:
// CloudGoat's terraform declares the misconfigurations, so indexing it gives their ground truth
// directly rather than a fixture we author.
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
		t.Error("indexed nothing — CloudGoat terraform is not consumable by this indexer as-is")
	}
}
