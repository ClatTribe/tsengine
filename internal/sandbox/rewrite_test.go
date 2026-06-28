package sandbox

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestRewriteLoopbackArgs_RewritesKnownURLKeys(t *testing.T) {
	in := tool.Args{
		"target":    "http://localhost:8098/wavsep/",
		"login_url": "https://127.0.0.1/login",
		"targets":   "http://localhost/a\nhttp://127.0.0.1:8080/b",
		// non-URL key: must be left untouched even if it looks loopback.
		"data": "username=localhost&x=1",
	}
	out := rewriteLoopbackArgs(in)

	if got := out["target"].(string); got != "http://host.docker.internal:8098/wavsep/" {
		t.Errorf("target = %q", got)
	}
	if got := out["login_url"].(string); got != "https://host.docker.internal/login" {
		t.Errorf("login_url = %q", got)
	}
	if got := out["targets"].(string); got != "http://host.docker.internal/a\nhttp://host.docker.internal:8080/b" {
		t.Errorf("targets = %q", got)
	}
	if got := out["data"].(string); got != "username=localhost&x=1" {
		t.Errorf("data should be untouched, got %q", got)
	}
	// Original map must not be mutated (copy semantics).
	if in["target"].(string) != "http://localhost:8098/wavsep/" {
		t.Error("rewriteLoopbackArgs mutated the input map")
	}
}

func TestRewriteOneLoopback(t *testing.T) {
	cases := map[string]string{
		"http://localhost:8098/x": "http://host.docker.internal:8098/x",
		"https://127.0.0.1/y":     "https://host.docker.internal/y",
		// 0.0.0.0 is NOT rewritten (not a legit target + SSRF-bypass token) — it stays pointing at the sandbox.
		"http://0.0.0.0:3000": "http://0.0.0.0:3000",
		"localhost:8080":      "host.docker.internal:8080",
		"127.0.0.1":               "host.docker.internal",
		"localhost":               "host.docker.internal",
		// Must NOT rewrite a non-loopback host that merely contains the token.
		"http://localhosting.example.com/z": "http://localhosting.example.com/z",
		"http://example.com/localhost":      "http://example.com/localhost",
		"https://10.0.0.5:443/api":          "https://10.0.0.5:443/api",
	}
	for in, want := range cases {
		if got := rewriteOneLoopback(in); got != want {
			t.Errorf("rewriteOneLoopback(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildRunArgs_AddsHostGatewayAlias(t *testing.T) {
	args := buildRunArgs(SpawnOptions{Image: "img"}, 1234, "tok")
	found := false
	for i, a := range args {
		if a == "--add-host" && i+1 < len(args) && args[i+1] == "host.docker.internal:host-gateway" {
			found = true
		}
	}
	if !found {
		t.Errorf("buildRunArgs must add --add-host host.docker.internal:host-gateway; got %v", args)
	}
}
