// Package sandbox is the host-side adapter to the strix-sandbox Docker
// container. It owns the container lifecycle (Spawn/Destroy) and the
// HTTP client that dispatches tools to the tool-server inside the
// container. See CLAUDE.md §12 for the host/sandbox boundary discipline.
package sandbox

// Info describes a running sandbox container — enough for the orchestrator
// to dispatch tools into it and tear it down. Fields are stable and
// included in vulnerabilities.json (Engine.SandboxImageDigest).
type Info struct {
	// ContainerID is the docker container ID returned by `docker run -d`.
	ContainerID string

	// APIURL is the http://host:port endpoint of the tool-server inside
	// the container (host port, not container port — host-side accesses
	// via the published port).
	APIURL string

	// AuthToken is the bearer token the tool-server validates on /execute.
	// Generated per scan; never written to disk.
	AuthToken string

	// ImageDigest is the sha256:... digest of the image used.
	// Recorded into Scan.Engine.SandboxImageDigest for reproducibility
	// (CLAUDE.md §10).
	ImageDigest string

	// Image is the human-readable image reference (e.g. "tsengine/sandbox:0.1.0").
	Image string

	// Port is the host port the tool-server is published on.
	Port int
}
