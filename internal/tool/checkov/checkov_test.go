package checkov

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_SingleFramework(t *testing.T) {
	blob := []byte(`{"results":{"failed_checks":[
	  {"check_id":"CKV_AWS_20","check_name":"S3 bucket not public","file_path":"/main.tf","severity":"HIGH","resource":"aws_s3_bucket.b"}
	]}}`)
	out := parse(blob)
	if len(out) != 1 {
		t.Fatalf("got %d, want 1", len(out))
	}
	if out[0].RuleID != "checkov::CKV_AWS_20" || out[0].Severity != types.SeverityHigh {
		t.Errorf("finding = %+v", out[0])
	}
	if out[0].Endpoint != "/main.tf:aws_s3_bucket.b" {
		t.Errorf("endpoint = %q", out[0].Endpoint)
	}
}

func TestParse_MultiFrameworkArrayAndDefaultSeverity(t *testing.T) {
	blob := []byte(`[
	  {"results":{"failed_checks":[{"check_id":"CKV_K8S_1","check_name":"x","file_path":"/d.yaml","resource":"Pod.a"}]}},
	  {"results":{"failed_checks":[{"check_id":"CKV_DOCKER_2","check_name":"y","file_path":"/Dockerfile","resource":"FROM"}]}}
	]`)
	out := parse(blob)
	if len(out) != 2 {
		t.Fatalf("got %d, want 2 across frameworks", len(out))
	}
	// Empty severity defaults to medium (a failed IaC check isn't info).
	if out[0].Severity != types.SeverityMedium {
		t.Errorf("default severity = %q, want medium", out[0].Severity)
	}
}

func TestCheckov_Identity(t *testing.T) {
	if _, ok := tool.Get("checkov"); !ok {
		t.Error("checkov not registered")
	}
}
