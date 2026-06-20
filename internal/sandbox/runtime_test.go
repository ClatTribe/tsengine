package sandbox

import (
	"os"
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

func TestBuildRunArgs_HardeningFlags(t *testing.T) {
	args := buildRunArgs(SpawnOptions{
		Image: "img:1",
		Hardening: Hardening{
			Memory: "4g", CPUs: "2", PidsLimit: "1024", NoFile: "4096", TmpfsTmp: "512m",
			ReadOnly: true, User: "65534:65534", Network: "tsengine-sandbox",
		},
	}, 1, "t")
	s := argsString(args)
	for _, want := range []string{
		"--read-only",
		"--tmpfs /tmp:rw,nosuid,nodev,size=512m",
		"--user 65534:65534",
		"--network tsengine-sandbox",
		"--memory 4g",
		"--cpus 2",
		"--pids-limit 1024",
		"--ulimit nofile=4096",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("hardening flag missing %q: %s", want, s)
		}
	}
	if args[len(args)-1] != "img:1" {
		t.Errorf("image must still be last: %s", s)
	}
}

func TestBuildRunArgs_ZeroHardeningOmitsFlags(t *testing.T) {
	// A zero Hardening (buildRunArgs is pure; Spawn fills env defaults upstream) must
	// add no confinement flags — keeps the dev/test path unchanged.
	s := argsString(buildRunArgs(SpawnOptions{Image: "img:1"}, 1, "t"))
	for _, absent := range []string{"--read-only", "--tmpfs", "--user", "--network", "--memory", "--cpus", "--pids-limit", "--ulimit"} {
		if strings.Contains(s, absent) {
			t.Errorf("zero Hardening should not add %q: %s", absent, s)
		}
	}
}

func TestBuildRunArgs_ReadOnlyWithoutTmpfsStillReadOnly(t *testing.T) {
	s := argsString(buildRunArgs(SpawnOptions{Image: "img:1", Hardening: Hardening{ReadOnly: true}}, 1, "t"))
	if !strings.Contains(s, "--read-only") || strings.Contains(s, "--tmpfs") {
		t.Errorf("read-only without a tmpfs size should set --read-only and no --tmpfs: %s", s)
	}
}

func TestHardeningFromEnv(t *testing.T) {
	// Defaults when nothing is set. Truly UNSET the keys (LookupEnv distinguishes
	// set-but-empty from unset), restoring on cleanup.
	clearSandboxEnv(t)
	d := HardeningFromEnv()
	if d != DefaultHardening() {
		t.Errorf("no env → defaults, got %+v", d)
	}

	// Overlay + the "disable" sentinel + opt-in controls.
	t.Setenv("TSENGINE_SANDBOX_MEMORY", "8g")
	t.Setenv("TSENGINE_SANDBOX_CPUS", "off") // sentinel → no limit
	t.Setenv("TSENGINE_SANDBOX_READONLY", "1")
	t.Setenv("TSENGINE_SANDBOX_USER", "1000:1000")
	t.Setenv("TSENGINE_SANDBOX_NETWORK", "isolated-net")
	h := HardeningFromEnv()
	if h.Memory != "8g" {
		t.Errorf("memory override: got %q", h.Memory)
	}
	if h.CPUs != "" {
		t.Errorf("'off' should disable cpus, got %q", h.CPUs)
	}
	if !h.ReadOnly || h.User != "1000:1000" || h.Network != "isolated-net" {
		t.Errorf("opt-in controls not applied: %+v", h)
	}
	// Untouched fields keep their defaults.
	if h.PidsLimit != "1024" || h.TmpfsTmp != "512m" {
		t.Errorf("untouched defaults changed: %+v", h)
	}
}

// clearSandboxEnv truly unsets all TSENGINE_SANDBOX_* keys for the test, restoring
// each one's prior value on cleanup.
func clearSandboxEnv(t *testing.T) {
	for _, k := range []string{
		"TSENGINE_SANDBOX_MEMORY", "TSENGINE_SANDBOX_CPUS", "TSENGINE_SANDBOX_PIDS",
		"TSENGINE_SANDBOX_NOFILE", "TSENGINE_SANDBOX_TMPFS_TMP", "TSENGINE_SANDBOX_READONLY",
		"TSENGINE_SANDBOX_USER", "TSENGINE_SANDBOX_NETWORK",
	} {
		k := k
		if prev, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, prev) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		_ = os.Unsetenv(k)
	}
}
