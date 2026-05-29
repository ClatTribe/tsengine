package codeql

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseSARIF_Results(t *testing.T) {
	blob := []byte(`{"runs":[{"results":[
	  {"ruleId":"java/sql-injection","message":{"text":"User input flows to SQL query"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/Db.java"},"region":{"startLine":42}}}]}
	]}]}`)
	out := parseSARIF(blob, "java")
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "codeql::java/sql-injection" || f.Severity != types.SeverityHigh {
		t.Errorf("finding = %+v", f)
	}
	if f.Endpoint != "src/Db.java:42" {
		t.Errorf("endpoint = %q, want src/Db.java:42", f.Endpoint)
	}
}

func TestParseSARIF_Empty(t *testing.T) {
	if parseSARIF([]byte(`{"runs":[{"results":[]}]}`), "go") != nil {
		t.Error("no results → nil")
	}
	if parseSARIF(nil, "go") != nil {
		t.Error("nil blob → nil")
	}
}

func TestCodeQL_Identity(t *testing.T) {
	if _, ok := tool.Get("codeql"); !ok {
		t.Error("codeql not registered")
	}
}
