package sandbox

import (
	"strings"
	"testing"
)

func argsString(a []string) string { return strings.Join(a, " ") }

func TestBuildRunArgs_Hardening(t *testing.T) {
	args := buildRunArgs(SpawnOptions{Image: "img:1"}, 12345, "tok")
	s := argsString(args)
	for _, want := range []string{"--cap-drop=ALL", "no-new-privileges", "127.0.0.1:12345:8080", "TSENGINE_AUTH_TOKEN=tok"} {
		if !strings.Contains(s, want) {
			t.Errorf("args missing %q: %s", want, s)
		}
	}
	if args[len(args)-1] != "img:1" {
		t.Errorf("image must be last arg: %s", s)
	}
}

func TestBuildRunArgs_MountsAreReadOnly(t *testing.T) {
	args := buildRunArgs(SpawnOptions{
		Image:  "img:1",
		Mounts: []Mount{{HostPath: "/host/repo", ContainerPath: "/workspace"}},
	}, 1, "t")
	s := argsString(args)
	if !strings.Contains(s, "-v /host/repo:/workspace:ro") {
		t.Errorf("mount not read-only or missing: %s", s)
	}
}

func TestBuildRunArgs_EnvPassthrough(t *testing.T) {
	args := buildRunArgs(SpawnOptions{
		Image: "img:1",
		Env:   []string{"AWS_ACCESS_KEY_ID=AKIA", "AWS_REGION=us-east-1"},
	}, 1, "t")
	s := argsString(args)
	if !strings.Contains(s, "-e AWS_ACCESS_KEY_ID=AKIA") || !strings.Contains(s, "-e AWS_REGION=us-east-1") {
		t.Errorf("env not passed through: %s", s)
	}
}

func TestBuildRunArgs_ExtraHosts(t *testing.T) {
	args := buildRunArgs(SpawnOptions{
		Image:      "img:1",
		ExtraHosts: map[string]string{"host.docker.internal": "host-gateway"},
	}, 1, "t")
	if !strings.Contains(argsString(args), "--add-host host.docker.internal:host-gateway") {
		t.Errorf("extra host missing: %s", argsString(args))
	}
}
