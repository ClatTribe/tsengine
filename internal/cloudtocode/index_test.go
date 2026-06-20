package cloudtocode

import (
	"path/filepath"
	"testing"
)

func TestIndexDir_CapturesResourcesWithLineAndIdentifiers(t *testing.T) {
	idx, err := IndexDir(filepath.Join("testdata", "iac"))
	if err != nil {
		t.Fatalf("IndexDir: %v", err)
	}

	byAddr := map[string]Resource{}
	for _, r := range idx {
		byAddr[r.Address()] = r
	}

	// aws_s3_bucket.assets at s3.tf:1, with the physical name + tag value captured.
	assets, ok := byAddr["aws_s3_bucket.assets"]
	if !ok {
		t.Fatalf("missing aws_s3_bucket.assets; got %v", keys(byAddr))
	}
	if assets.File != "s3.tf" || assets.Line != 1 {
		t.Errorf("assets location = %s:%d, want s3.tf:1", assets.File, assets.Line)
	}
	if !hasID(assets.Identifiers, "acme-prod-assets") {
		t.Errorf("assets identifiers missing physical name: %v", assets.Identifiers)
	}

	// The logs bucket uses an interpolation (var.x) — no literal physical name,
	// so only the logical name is an identifier (degrades honestly).
	logs, ok := byAddr["aws_s3_bucket.logs"]
	if !ok {
		t.Fatalf("missing aws_s3_bucket.logs")
	}
	if logs.Line != 10 {
		t.Errorf("logs line = %d, want 10", logs.Line)
	}
	if hasID(logs.Identifiers, "var.logs_bucket_name") {
		t.Errorf("interpolation should not be captured as a literal: %v", logs.Identifiers)
	}

	// Security group physical name captured.
	sg := byAddr["aws_security_group.web"]
	if !hasID(sg.Identifiers, "acme-web-sg") {
		t.Errorf("sg identifiers missing name: %v", sg.Identifiers)
	}
}

func keys(m map[string]Resource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
