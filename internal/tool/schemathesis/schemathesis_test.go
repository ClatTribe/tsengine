package schemathesis

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_JUnitFailuresAndErrors(t *testing.T) {
	report := []byte(`<?xml version="1.0"?>
	<testsuites><testsuite>
	  <testcase name="GET /users/{id}"><failure message="server error 500"/></testcase>
	  <testcase name="POST /login"><error message="connection reset"/></testcase>
	  <testcase name="GET /health"></testcase>
	</testsuite></testsuites>`)
	out := parse(report)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2 (failure + error; passing skipped)", len(out))
	}
	if out[0].Endpoint != "GET /users/{id}" || out[0].Severity != types.SeverityMedium {
		t.Errorf("finding[0] = %+v", out[0])
	}
	if out[0].RuleID != "schemathesis::contract-violation" {
		t.Errorf("RuleID = %q", out[0].RuleID)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestSchemathesis_Identity(t *testing.T) {
	if _, ok := tool.Get("schemathesis"); !ok {
		t.Error("schemathesis not registered")
	}
}
