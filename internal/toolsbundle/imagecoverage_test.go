package toolsbundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// TestSandboxImageProvidesEveryToolBinary closes the third failure mode in the §12.7 wiring rule.
//
// cmd/tool-server's TestHostSandboxRegistryParity already guards the first two: a tool registered on
// only one side of the host/sandbox boundary. But registration parity is necessary, NOT sufficient — a
// tool can be correctly registered in BOTH views and still be unrunnable, because the sandbox image
// never got its binary. That failure looks identical to a clean scan: the dispatch succeeds, the exec
// fails, and the finding simply never appears.
//
// Both live examples were exactly that shape:
//
//   - gosec       — `go install`ed in the builder stage but never COPY'd into the final stage.
//   - govulncheck — registered on both sides, absent from the Dockerfile entirely.
//
// So this asserts the remaining link: every registered tool that shells out has its name somewhere in
// the sandbox Dockerfile. It is deliberately a coarse textual check rather than a real image build —
// it runs in the normal `go test ./...` gate with no Docker daemon, and it is enough to catch a tool
// added to the registry with no image work at all, which is how both bugs got in.
func TestSandboxImageProvidesEveryToolBinary(t *testing.T) {
	root := repoRoot(t)

	df, err := os.ReadFile(filepath.Join(root, "docker", "sandbox", "Dockerfile"))
	if err != nil {
		t.Fatalf("read sandbox Dockerfile: %v", err)
	}
	dockerfile := strings.ToLower(string(df))

	if len(tool.All()) < 40 {
		t.Fatalf("registry has only %d tools — the bundle's init() didn't run, so this proves nothing", len(tool.All()))
	}

	// Wrappers that do their work IN-PROCESS (HTTP / native Go) need no binary in the image. Keyed by the
	// registered Tool.Name(), which differs from the package dir for some (internal/tool/openapi
	// registers as "openapi_spec_ingest").
	inProcess := map[string]bool{
		"crtsh":               true, // crt.sh JSON API over HTTPS
		"api_response_sample": true, // unauthenticated GET + classify via internal/dataclass
		"openapi_spec_ingest": true, // spec fetch + parse
		"seed_auth":           true, // form/passthrough login via net/http
	}

	for _, tl := range tool.All() {
		name := tl.Name()
		if inProcess[name] {
			continue
		}
		// A wrapper's name and its binary can differ (kiterunner ships as `kr`), and the Dockerfile may
		// name it via an install URL rather than the bare binary, so accept the name in any of its usual
		// spellings anywhere in the file.
		found := false
		for _, p := range []string{name, strings.ReplaceAll(name, "_", "-"), strings.ReplaceAll(name, "-", "")} {
			if strings.Contains(dockerfile, strings.ToLower(p)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tool %q is registered but never appears in docker/sandbox/Dockerfile — it would be "+
				"dispatchable yet unrunnable, and the scan would look clean instead of failing. Install the "+
				"binary AND COPY it into the final stage.", name)
		}
	}
}

// TestGoInstalledToolsAreCopiedIntoFinalStage catches the narrower gosec bug directly: a binary
// `go install`ed in the builder stage that never reaches the runtime stage.
//
// The coverage test above would MISS this on its own — an installed-but-not-copied tool still has its
// name in the Dockerfile (on the install line), so a textual scan sees it. Only the install-vs-COPY
// diff proves the binary actually ships.
func TestGoInstalledToolsAreCopiedIntoFinalStage(t *testing.T) {
	root := repoRoot(t)
	df, err := os.ReadFile(filepath.Join(root, "docker", "sandbox", "Dockerfile"))
	if err != nil {
		t.Fatalf("read sandbox Dockerfile: %v", err)
	}
	body := string(df)

	copied := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "/go/bin/"); i >= 0 {
			rest := line[i+len("/go/bin/"):]
			copied[strings.Fields(rest)[0]] = true
		}
	}

	// binaryFor maps a `go install` module path to the binary name it produces, for the cases where the
	// last path segment isn't it (versioned module suffixes, renamed binaries).
	binaryFor := map[string]string{
		"v2": "", "v4": "", "v8": "", // module version suffixes — resolved below
		"kiterunner": "kr", // ships as `kr`
		"amass":      "amass",
	}

	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // a comment, not a build step ("`go install` is deterministic")
		}
		idx := strings.Index(line, "go install ")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[idx+len("go install "):])
		if len(fields) == 0 {
			continue
		}
		mod := strings.SplitN(fields[0], "@", 2)[0]
		// A real install target is a module path (host/segment/...), never a bare English word.
		if !strings.Contains(mod, "/") || !strings.Contains(mod, ".") {
			continue
		}
		mod = strings.TrimSuffix(mod, "/...")
		seg := mod[strings.LastIndex(mod, "/")+1:]

		bin, ok := binaryFor[seg]
		if ok && bin == "" {
			// versioned suffix (…/v2) — the real binary is the segment before it
			trimmed := mod[:strings.LastIndex(mod, "/")]
			seg = trimmed[strings.LastIndex(trimmed, "/")+1:]
		} else if ok {
			seg = bin
		}
		if b, ok := binaryFor[seg]; ok && b != "" {
			seg = b
		}

		if !copied[seg] {
			t.Errorf("%q is `go install`ed in the builder stage but never COPY'd from /go/bin into the "+
				"final stage — the binary does not ship, so exec(%q) fails at runtime (this is exactly how "+
				"gosec was broken). Add: COPY --from=builder /go/bin/%s /usr/local/bin/%s",
				seg, seg, seg, seg)
		}
	}
}
