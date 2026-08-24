package toolsbundle

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestVerifyToolsListMatchesTheWrappers keeps docker/sandbox/verify-tools.sh honest.
//
// That script is the build-time assertion that a TOOLSET=full image really CONTAINS its scanners —
// the check codeql and kics needed and did not have. It works from a hardcoded binary list, and a
// hardcoded list is only as good as whatever stops it drifting: a wrapper that starts shelling out
// to a new binary, with no entry here, would go unverified forever, which is the same shape as the
// textual coverage test passing while two tools were absent.
//
// So the list is compared against the binaries the wrappers ACTUALLY exec.
func TestVerifyToolsListMatchesTheWrappers(t *testing.T) {
	root := repoRoot(t)

	script, err := os.ReadFile(filepath.Join(root, "docker", "sandbox", "verify-tools.sh"))
	if err != nil {
		t.Fatalf("read verify-tools.sh: %v — the Dockerfile runs it as its final step; if it moved, "+
			"move this guard with it rather than letting the check stop seeing its subject", err)
	}
	declared := map[string]bool{}
	if m := regexp.MustCompile(`(?s)BINARIES="([^"]+)"`).FindSubmatch(script); m != nil {
		for _, b := range strings.Fields(string(m[1])) {
			declared[b] = true
		}
	}
	if len(declared) < 30 {
		t.Fatalf("only parsed %d binaries out of verify-tools.sh — the BINARIES block has changed shape "+
			"and this guard is no longer reading it", len(declared))
	}

	// What the wrappers really run. Read from source rather than the registry because the binary name
	// is not the tool name (kiterunner ships as `kr`, scoutsuite as `scout`).
	execRe := regexp.MustCompile(`exec\.CommandContext\(ctx, "([a-z0-9_.-]+)"`)
	used := map[string]bool{}
	toolDir := filepath.Join(root, "internal", "tool")
	entries, err := os.ReadDir(toolDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(toolDir, e.Name(), "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, m := range execRe.FindAllSubmatch(b, -1) {
				used[string(m[1])] = true
			}
		}
	}
	if len(used) < 30 {
		t.Fatalf("only found %d exec'd binaries across the wrappers — the pattern has stopped matching", len(used))
	}

	var unverified, stale []string
	for b := range used {
		if !declared[b] {
			unverified = append(unverified, b)
		}
	}
	for b := range declared {
		if !used[b] {
			stale = append(stale, b)
		}
	}
	sort.Strings(unverified)
	sort.Strings(stale)

	if len(unverified) > 0 {
		t.Errorf("wrapper(s) exec these binaries but verify-tools.sh does not check for them: %v.\n\n"+
			"A full image could ship without them and the build would pass — exactly how codeql and kics "+
			"went missing from every image. Add them to BINARIES.", unverified)
	}
	if len(stale) > 0 {
		t.Errorf("verify-tools.sh checks for binaries no wrapper runs: %v.\n\nEither a wrapper was "+
			"deleted (drop the entry) or the binary name is wrong — a check for a name nothing uses "+
			"fails the build for no reason, which is how a guard gets disabled.", stale)
	}
}
