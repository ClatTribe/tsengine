package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SpawnOptions configures a sandbox container.
type SpawnOptions struct {
	// Image is the docker image reference (e.g. "tsengine/sandbox:0.1.0").
	// Required.
	Image string

	// HealthTimeout caps how long Spawn waits for the tool-server's
	// /healthz to return 200. Zero means 30s.
	HealthTimeout time.Duration

	// ExtraHosts adds --add-host entries. Used for host.docker.internal
	// on linux where Docker doesn't add it by default.
	ExtraHosts map[string]string

	// Mounts bind-mounts host paths into the container. Used by the
	// repository asset to expose source at /workspace. Mounts are
	// read-only by default — the engine never needs to write to a scan
	// target.
	Mounts []Mount

	// Env passes extra environment variables into the container. Used by
	// the cloud_account asset to forward scoped, short-lived cloud
	// credentials. Values live only for the container's lifetime
	// (--rm) and are never written to disk inside the sandbox.
	Env []string

	// Hardening is the per-sandbox security + resource confinement
	// (docs/production-single-box.md, threat model T1/T2/T4/T5). When left
	// zero, Spawn fills it from the environment (HardeningFromEnv) so the
	// safe defaults (resource limits + a writable /tmp tmpfs) always apply.
	Hardening Hardening
}

// Mount is a read-only bind mount from host into the sandbox container.
type Mount struct {
	HostPath      string
	ContainerPath string
}

// Hardening captures the security + resource confinement applied to each
// ephemeral sandbox. It is the single-box isolation control surface
// (docs/production-single-box.md §5 P1).
//
// Defaults (HardeningFromEnv) are chosen to confine WITHOUT breaking scans:
// resource/PID/file limits + a writable /tmp tmpfs apply to every sandbox
// (DoS protection, T5). The stricter controls — read-only rootfs, a non-root
// user, and an isolated network — are OPT-IN (empty/false by default) and are
// switched on by the production profile (docker-compose.prod.yml / the deploy
// script) once validated against the shipped sandbox image, so the default
// `docker run` path keeps working for dev + the existing E2E.
type Hardening struct {
	Memory    string // --memory (e.g. "4g"); "" → no limit
	CPUs      string // --cpus (e.g. "2"); "" → no limit
	PidsLimit string // --pids-limit (e.g. "1024"); "" → no limit
	NoFile    string // --ulimit nofile=<N>; "" → unset
	TmpfsTmp  string // size of a writable /tmp tmpfs (e.g. "512m"); "" → none
	ReadOnly  bool   // --read-only rootfs (opt-in; relies on the /tmp tmpfs for scratch)
	User      string // --user (e.g. "65534:65534" = nobody); "" → image default
	Network   string // --network (e.g. an isolated bridge); "" → docker default
}

// DefaultHardening returns the safe, non-breaking defaults: confine resources +
// PIDs + open files and give a writable /tmp, but do NOT force read-only rootfs,
// a non-root user, or a network (those are opt-in via env / the prod profile).
func DefaultHardening() Hardening {
	return Hardening{Memory: "4g", CPUs: "2", PidsLimit: "1024", NoFile: "4096", TmpfsTmp: "512m"}
}

// HardeningFromEnv overlays TSENGINE_SANDBOX_* env vars on DefaultHardening.
// A value of "off"/"none"/"0"/"unlimited" for a limit disables it (sets it "").
func HardeningFromEnv() Hardening {
	h := DefaultHardening()
	if v, ok := os.LookupEnv("TSENGINE_SANDBOX_MEMORY"); ok {
		h.Memory = unlimitable(v)
	}
	if v, ok := os.LookupEnv("TSENGINE_SANDBOX_CPUS"); ok {
		h.CPUs = unlimitable(v)
	}
	if v, ok := os.LookupEnv("TSENGINE_SANDBOX_PIDS"); ok {
		h.PidsLimit = unlimitable(v)
	}
	if v, ok := os.LookupEnv("TSENGINE_SANDBOX_NOFILE"); ok {
		h.NoFile = unlimitable(v)
	}
	if v, ok := os.LookupEnv("TSENGINE_SANDBOX_TMPFS_TMP"); ok {
		h.TmpfsTmp = unlimitable(v)
	}
	if v := os.Getenv("TSENGINE_SANDBOX_READONLY"); v == "1" || v == "true" {
		h.ReadOnly = true
	}
	h.User = strings.TrimSpace(os.Getenv("TSENGINE_SANDBOX_USER"))       // "" = image default
	h.Network = strings.TrimSpace(os.Getenv("TSENGINE_SANDBOX_NETWORK")) // "" = docker default
	return h
}

// unlimitable maps the "disable this limit" sentinels to "".
func unlimitable(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "none", "0", "unlimited":
		return ""
	}
	return strings.TrimSpace(v)
}

// isZero reports whether the Hardening is the zero value (caller left it unset →
// Spawn fills it from the environment).
func (h Hardening) isZero() bool { return h == Hardening{} }

// Spawn launches a sandbox container, waits for the tool-server's
// /healthz endpoint to become ready, and returns its Info.
//
// The caller MUST call Destroy with the returned Info to clean up the
// container — even on subsequent error paths.
func Spawn(ctx context.Context, opts SpawnOptions) (*Info, error) {
	if opts.Image == "" {
		return nil, errors.New("sandbox.Spawn: empty Image")
	}
	if opts.HealthTimeout == 0 {
		opts.HealthTimeout = 30 * time.Second
	}
	if opts.Hardening.isZero() {
		opts.Hardening = HardeningFromEnv()
	}

	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("sandbox.Spawn: generate token: %w", err)
	}

	port, err := pickFreePort()
	if err != nil {
		return nil, fmt.Errorf("sandbox.Spawn: pick port: %w", err)
	}

	args := buildRunArgs(opts, port, token)

	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("sandbox.Spawn: docker run: %w (%s)", err, exitStderr(err))
	}
	containerID := strings.TrimSpace(string(out))
	if containerID == "" {
		return nil, errors.New("sandbox.Spawn: empty container id from docker run")
	}

	digest, err := imageDigest(ctx, opts.Image)
	if err != nil {
		// Best-effort — proceed without if we can't resolve, but warn.
		digest = ""
	}

	info := &Info{
		ContainerID: containerID,
		APIURL:      fmt.Sprintf("http://127.0.0.1:%d", port),
		AuthToken:   token,
		ImageDigest: digest,
		Image:       opts.Image,
		Port:        port,
	}

	if err := waitHealthy(ctx, info, opts.HealthTimeout); err != nil {
		// Clean up before returning the error.
		_ = Destroy(context.Background(), info)
		return nil, fmt.Errorf("sandbox.Spawn: wait healthy: %w", err)
	}

	return info, nil
}

// Destroy stops the container. Errors are logged but not returned past the
// stop failure — container destruction must be best-effort because Spawn's
// error paths call it.
func Destroy(ctx context.Context, info *Info) error {
	if info == nil || info.ContainerID == "" {
		return nil
	}
	// `docker run --rm` removes on stop; stop is sufficient.
	// gosec G204: binary is literal "docker"; ContainerID was produced by our
	// own `docker run` and is not user-controlled.
	out, err := exec.CommandContext(ctx, "docker", "stop", "-t", "2", info.ContainerID).CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("sandbox.Destroy: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitHealthy polls the tool-server's /healthz until it returns 200 or
// timeout elapses.
func waitHealthy(ctx context.Context, info *Info, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := newHTTPClient(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("tool-server not ready after %s", timeout)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		req, _ := requestWithCtx(ctx, "GET", info.APIURL+"/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// buildRunArgs assembles the `docker run` argv. Pure function so the
// mount / env / hardening flags are unit-testable without docker.
func buildRunArgs(opts SpawnOptions, port int, token string) []string {
	args := []string{
		"run", "-d", "--rm",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", port),
		"-e", "TSENGINE_AUTH_TOKEN=" + token,
		"--cap-drop=ALL",
		"--security-opt", "no-new-privileges",
		// Make host.docker.internal resolve to the host gateway from
		// inside the sandbox. Docker Desktop (macOS/Windows) injects this
		// automatically, but Linux does not — without it, a target the
		// client rewrites to host.docker.internal (see client.go
		// rewriteLoopbackArgs) is unreachable and network probes silently
		// fail. strix lost a full ip_address benchmark to exactly this
		// (recall 1.0→0.0). The alias is harmless where it already exists.
		"--add-host", "host.docker.internal:host-gateway",
	}

	// Per-sandbox hardening (docs/production-single-box.md §5 P1). Limits + a
	// writable /tmp tmpfs apply by default; read-only rootfs / non-root user /
	// isolated network are opt-in (empty by default).
	h := opts.Hardening
	if h.ReadOnly {
		args = append(args, "--read-only")
	}
	if h.TmpfsTmp != "" {
		// nosuid+nodev: a writable scratch dir must not become a privilege vector.
		args = append(args, "--tmpfs", "/tmp:rw,nosuid,nodev,size="+h.TmpfsTmp)
	}
	if h.User != "" {
		args = append(args, "--user", h.User)
	}
	if h.Network != "" {
		args = append(args, "--network", h.Network)
	}
	if h.Memory != "" {
		args = append(args, "--memory", h.Memory)
	}
	if h.CPUs != "" {
		args = append(args, "--cpus", h.CPUs)
	}
	if h.PidsLimit != "" {
		args = append(args, "--pids-limit", h.PidsLimit)
	}
	if h.NoFile != "" {
		args = append(args, "--ulimit", "nofile="+h.NoFile)
	}

	for hostname, ip := range opts.ExtraHosts {
		args = append(args, "--add-host", hostname+":"+ip)
	}
	for _, m := range opts.Mounts {
		// Always :ro — scan targets are never written to.
		args = append(args, "-v", fmt.Sprintf("%s:%s:ro", m.HostPath, m.ContainerPath))
	}
	for _, e := range opts.Env {
		args = append(args, "-e", e)
	}
	return append(args, opts.Image)
}

func generateToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// pickFreePort asks the kernel for an unused TCP port.
func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// imageDigest returns the local image's repo digest if available.
func imageDigest(ctx context.Context, image string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.Id}}", image).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func exitStderr(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return strings.TrimSpace(string(ee.Stderr))
	}
	return ""
}
