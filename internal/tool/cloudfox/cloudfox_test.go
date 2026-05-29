package cloudfox

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestCloudFox_RequiresProvider(t *testing.T) {
	if _, err := New().Run(context.Background(), tool.Args{}); err == nil {
		t.Error("expected error without a provider")
	}
	if _, err := New().Run(context.Background(), tool.Args{"target": "digitalocean"}); err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestCloudFox_Identity(t *testing.T) {
	c := New()
	if c.Name() != "cloudfox" || !c.SandboxExecution() {
		t.Error("identity wrong")
	}
	if _, ok := tool.Get("cloudfox"); !ok {
		t.Error("cloudfox not registered")
	}
}

func TestCloudFox_KnownArgs(t *testing.T) {
	got := map[string]bool{}
	for _, k := range New().KnownArgs() {
		got[k] = true
	}
	if !got["target"] || !got["command"] {
		t.Errorf("KnownArgs = %v, want target+command", New().KnownArgs())
	}
}
