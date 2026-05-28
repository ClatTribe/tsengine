package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
}

// Mount is a read-only bind mount from host into the sandbox container.
type Mount struct {
	HostPath      string
	ContainerPath string
}

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
	out, err := exec.CommandContext(ctx, "docker", "stop", "-t", "2", info.ContainerID).CombinedOutput()
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
