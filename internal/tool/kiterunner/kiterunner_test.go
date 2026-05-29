package kiterunner

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestParse_Routes(t *testing.T) {
	out := []byte(`
GET    200 [  1234,   56,    7] https://api.x/v1/admin   0cf6841b
POST   401 [    12,    2,    1] https://api.x/internal/debug   aa11bb
GET    200 [  1234,   56,    7] https://api.x/v1/admin   0cf6841b
banner noise line ignored
`)
	findings, surface := parse(out)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (dup collapsed, noise dropped)", len(findings))
	}
	if findings[0].RuleID != "kiterunner::undocumented-route" || findings[0].Endpoint != "https://api.x/v1/admin" {
		t.Errorf("finding[0] = %+v", findings[0])
	}
	if len(surface) != 2 || surface[1] != "POST https://api.x/internal/debug" {
		t.Errorf("surface = %v", surface)
	}
}

func TestParse_Empty(t *testing.T) {
	if f, s := parse(nil); f != nil || s != nil {
		t.Error("nil expected")
	}
}

func TestKiterunner_Identity(t *testing.T) {
	if _, ok := tool.Get("kiterunner"); !ok {
		t.Error("kiterunner not registered")
	}
}
