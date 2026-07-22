package sandbox

import (
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/execpolicy"
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

func TestBuildRunArgs_NetworkOmitsHostPort(t *testing.T) {
	// On an isolated network we must NOT publish a host port (a containerized platform
	// can't reach the host's 127.0.0.1); the platform connects by container IP instead.
	netArgs := argsString(buildRunArgs(SpawnOptions{Image: "img:1", Hardening: Hardening{Network: "iso"}}, 9999, "t"))
	if strings.Contains(netArgs, "-p ") || strings.Contains(netArgs, "127.0.0.1:9999") {
		t.Errorf("network mode must not publish a host port: %s", netArgs)
	}
	if !strings.Contains(netArgs, "--network iso") {
		t.Errorf("network mode should join the network: %s", netArgs)
	}
	// Without a network (dev / host-run), the host port IS published.
	noNet := argsString(buildRunArgs(SpawnOptions{Image: "img:1"}, 9999, "t"))
	if !strings.Contains(noNet, "-p 127.0.0.1:9999:8080") {
		t.Errorf("no-network mode must publish the loopback host port: %s", noNet)
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

// --- Escape-boundary regression tests (containment campaign item #6) ---
//
// These lock the sandbox's fail-closed confinement in place so a future change
// to buildRunArgs / ConfinementFlags cannot silently weaken it (the class of
// mistake the OpenAI×HuggingFace incident turned on — a compromised tool that
// could break out of its box). They assert the boundary holds regardless of the
// opt-in Hardening profile, and that no spawn path ever disables it.

// TestConfinementFlags_AlwaysOn: the always-on flags are present for EVERY
// hardening profile — zero, default, and strict — never conditional on env.
func TestBuildRunArgs_ConfinementFlagsAlwaysPresent(t *testing.T) {
	profiles := map[string]Hardening{
		"zero":    {},
		"default": DefaultHardening(),
		"strict":  StrictHardening("tsengine-sandbox"),
	}
	for name, h := range profiles {
		s := argsString(buildRunArgs(SpawnOptions{Image: "img:1", Hardening: h}, 1, "t"))
		if !strings.Contains(s, "--cap-drop=ALL") {
			t.Errorf("%s profile: must always drop ALL caps: %s", name, s)
		}
		if !strings.Contains(s, "--security-opt no-new-privileges") {
			t.Errorf("%s profile: must always forbid privilege escalation: %s", name, s)
		}
	}
}

// TestBuildRunArgs_NeverWeakensConfinement: the spawn argv must NEVER contain a
// flag that would disable the escape boundary — no --privileged, and no
// seccomp/apparmor unconfined (which would strip Docker's default syscall +
// MAC profiles). Probe across every knob a caller controls, incl. attacker-
// influenced env/mounts, so a value can't smuggle one of these in.
func TestBuildRunArgs_NeverWeakensConfinement(t *testing.T) {
	forbidden := []string{"--privileged", "seccomp=unconfined", "apparmor=unconfined", "--cap-add"}
	cases := []SpawnOptions{
		{Image: "img:1"},
		{Image: "img:1", Hardening: StrictHardening("iso")},
		{Image: "img:1", Hardening: DefaultHardening()},
		// hostile-looking env/mount values must not change the security flags.
		{Image: "img:1", Env: []string{"X=--privileged", "Y=seccomp=unconfined"}},
		{Image: "img:1", Mounts: []Mount{{HostPath: "/etc", ContainerPath: "/x --privileged"}}},
	}
	for i, opts := range cases {
		s := argsString(buildRunArgs(opts, 1, "t"))
		for _, bad := range forbidden {
			// --privileged / unconfined must never appear as an actual docker flag.
			// (Env/mount VALUES that merely contain the substring are fine — they're
			// after -e/-v, not standalone flags — so assert on flag position.)
			if hasStandaloneFlag(s, bad) {
				t.Errorf("case %d: confinement-weakening flag %q present: %s", i, bad, s)
			}
		}
	}
}

// hasStandaloneFlag reports whether `flag` appears as its own argv token (a real
// docker flag), not merely as a substring inside an -e/-v value.
func hasStandaloneFlag(argv, flag string) bool {
	for _, tok := range strings.Fields(argv) {
		if tok == flag {
			return true
		}
	}
	return false
}

// TestStrictHardening_FailClosed: the production preset is read-only rootfs +
// a NON-root user + an isolated network + the resource caps.
func TestStrictHardening_FailClosed(t *testing.T) {
	h := StrictHardening("tsengine-sandbox")
	if !h.ReadOnly {
		t.Error("strict must force a read-only rootfs")
	}
	if h.User == "" || strings.HasPrefix(h.User, "0:") || h.User == "0" || h.User == "root" {
		t.Errorf("strict must run as a non-root user, got %q", h.User)
	}
	if h.Network == "" {
		t.Error("strict must join an isolated network")
	}
	for _, cap := range []string{h.Memory, h.CPUs, h.PidsLimit, h.NoFile} {
		if cap == "" {
			t.Errorf("strict must keep the resource caps, got %+v", h)
		}
	}
	// And it must actually render those flags in the spawn argv.
	s := argsString(buildRunArgs(SpawnOptions{Image: "img:1", Hardening: h}, 1, "t"))
	for _, want := range []string{"--read-only", "--user 65534:65534", "--network tsengine-sandbox"} {
		if !strings.Contains(s, want) {
			t.Errorf("strict spawn argv missing %q: %s", want, s)
		}
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

// TestBuildRunArgs_InjectsPolicy: a spawn-time capability envelope is baked into the container as
// TSENGINE_EXEC_POLICY, so the tool-server enforces scope even if the caller is later compromised.
func TestBuildRunArgs_InjectsPolicy(t *testing.T) {
	p := &execpolicy.Policy{Tools: []string{"nuclei"}, Hosts: []string{"app.acme.com"}, MaxRequests: 50}
	args := buildRunArgs(SpawnOptions{Image: "img:1", Policy: p}, 12345, "tok")
	got := argsString(args)
	if !strings.Contains(got, "TSENGINE_EXEC_POLICY=") {
		t.Fatalf("policy must be injected as an env var, got: %s", got)
	}
	// and the encoded policy must carry the real scope (so it's not an empty envelope)
	if !strings.Contains(got, "nuclei") || !strings.Contains(got, "app.acme.com") {
		t.Errorf("injected policy must carry the tools/hosts, got: %s", got)
	}
	// no policy → no env var (back-compat)
	if strings.Contains(argsString(buildRunArgs(SpawnOptions{Image: "img:1"}, 1, "t")), "TSENGINE_EXEC_POLICY") {
		t.Error("nil policy must not inject the env var")
	}
}
