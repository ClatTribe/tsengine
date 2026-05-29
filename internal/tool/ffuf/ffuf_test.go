package ffuf

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestParse_Results(t *testing.T) {
	blob := []byte(`{"results":[
	  {"url":"https://x/admin","status":200,"length":1024},
	  {"url":"https://x/.git/config","status":200,"length":92}
	]}`)
	findings, surface := parse(blob)
	if len(findings) != 2 || len(surface) != 2 {
		t.Fatalf("findings=%d surface=%d, want 2/2", len(findings), len(surface))
	}
	if findings[0].RuleID != "ffuf::content-discovered" || findings[0].Endpoint != "https://x/admin" {
		t.Errorf("finding[0] = %+v", findings[0])
	}
	if surface[1] != "https://x/.git/config" {
		t.Errorf("surface[1] = %q", surface[1])
	}
}

func TestParse_Empty(t *testing.T) {
	if f, s := parse(nil); f != nil || s != nil {
		t.Error("nil expected")
	}
}

func TestFFUF_Identity(t *testing.T) {
	if _, ok := tool.Get("ffuf"); !ok {
		t.Error("ffuf not registered")
	}
}
