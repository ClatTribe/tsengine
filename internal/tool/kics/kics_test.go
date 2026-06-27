package kics

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A representative kics results.json: a HIGH S3-encryption query with two offending files, and a MEDIUM query.
const fixture = `{
  "queries": [
    {"query_name":"S3 Bucket Without Encryption","query_id":"abc-123","severity":"HIGH","files":[
      {"file_name":"s3.tf","line":10},
      {"file_name":"modules/data/s3.tf","line":4}
    ]},
    {"query_name":"Security Group With Wide-Open Ingress","query_id":"def-456","severity":"MEDIUM","files":[
      {"file_name":"sg.tf","line":22}
    ]}
  ],
  "severity_counters": {"HIGH": 2, "MEDIUM": 1}
}`

func TestParse_EmitsPerFileWithSeverity(t *testing.T) {
	out := parse([]byte(fixture))
	if len(out) != 3 { // 2 files for the S3 query + 1 for the SG query
		t.Fatalf("want 3 findings (per offending file), got %d: %+v", len(out), out)
	}
	var sawHigh, sawMedium bool
	for _, f := range out {
		if f.Tool != "kics" || f.Title == "" || f.Endpoint == "" {
			t.Errorf("missing core fields: %+v", f)
		}
		if f.RuleID == "kics::abc-123" && f.Severity == types.SeverityHigh {
			sawHigh = true
		}
		if f.RuleID == "kics::def-456" && f.Severity == types.SeverityMedium {
			sawMedium = true
		}
	}
	if !sawHigh || !sawMedium {
		t.Errorf("severity/rule-id mapping wrong: high=%v medium=%v", sawHigh, sawMedium)
	}
}

func TestParse_MalformedIsEmpty(t *testing.T) {
	if got := parse([]byte("not json")); got != nil {
		t.Errorf("malformed → no findings, got %+v", got)
	}
}
