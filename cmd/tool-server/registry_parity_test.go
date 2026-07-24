package main

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestHostSandboxRegistryParity guards the §12.7 wiring rule: every OSS tool must be registered in BOTH
// the host dispatch view (internal/toolsbundle — so a Handler can resolve/plan it) AND the sandbox
// execution view (cmd/tool-server/imports.go — so the tool-server can actually run it). A drift between
// them is the PR #588 class of silent failure, one that CI missed once at the anchor tier and again at
// the escalation/registry tier:
//
//   - a tool in toolsbundle but NOT the sandbox → dispatch 404s "unknown tool" at runtime (gosec/bandit/…);
//   - a tool in the sandbox but NOT toolsbundle → the host's tool.Get() returns !ok and the escalation
//     pass SILENTLY never fires (govulncheck reachability, wpscan WordPress depth).
//
// This asserts the two import sets are identical, modulo a tiny documented allowlist. It parses the
// files textually (not via the registry) precisely because the two live in different binaries and their
// blank-import lists are what actually diverge.
func TestHostSandboxRegistryParity(t *testing.T) {
	sandbox := toolImports(t, "imports.go")
	host := toolImports(t, "../../internal/toolsbundle/toolsbundle.go")

	// hostOnlyAllowed: tools intentionally registered on the host but not the sandbox. apkid is the anchor
	// for the DEPRECATED/descoped mobile_application asset (CLAUDE.md §3 — "do not build on it"); it can't
	// be dispatched in a meaningful scan, so its absence from the sandbox is acceptable, not a 404 risk.
	hostOnlyAllowed := map[string]bool{"apkid": true}

	for name := range host {
		if !sandbox[name] && !hostOnlyAllowed[name] {
			t.Errorf("tool %q is in internal/toolsbundle (host dispatch) but NOT cmd/tool-server/imports.go (sandbox exec) → dispatching it 404s at runtime. Add it to imports.go.", name)
		}
	}
	for name := range sandbox {
		if !host[name] {
			t.Errorf("tool %q is in cmd/tool-server/imports.go (sandbox exec) but NOT internal/toolsbundle (host dispatch) → the host's tool.Get(%q) returns !ok and any escalation using it SILENTLY never fires. Add it to toolsbundle.go.", name, name)
		}
	}

	if t.Failed() {
		t.Logf("host set: %v", sortedKeys(host))
		t.Logf("sandbox set: %v", sortedKeys(sandbox))
	}
}

var toolImportRe = regexp.MustCompile(`internal/tool/([a-z0-9_]+)"`)

func toolImports(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range toolImportRe.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatalf("no tool imports parsed from %s (regex/path drift?)", path)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
