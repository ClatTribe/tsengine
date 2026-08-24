package toolsbundle

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestToolsetGroupsCoverEveryDispatchingAsset is the guard for the per-asset SLIM sandbox images.
//
// # The bug
//
// docker/sandbox/toolset.sh gates each tool on an asset, so `TOOLSET=container` builds an image with
// only the container tools. That mechanism was written for `make sandbox-image-dev` — whose own help
// text says "partial coverage, dev only" — and was then used to publish per-asset PRODUCTION images.
//
// Tools do not belong to one asset. Measured against the handlers:
//
//	grype        gated on repository   — dispatched by container TOO
//	httpx        gated on web          — dispatched by api, domain AND ip
//	sqlmap       gated on web          — dispatched by api
//	schemathesis gated on api          — dispatched by web
//	modelscan    gated on ai           — dispatched by repository
//
// So `sandbox:container-latest` had no grype — a primary container CVE scanner — and three images had
// no httpx. Confirmed by building one: modelscan was genuinely absent from the repository image.
// A stubbed tool exits 127, which tool.DidNotRun reports honestly, so the scan degrades rather than
// lying — but the capability is gone and nobody learns until a customer's scan comes back thin.
//
// # Why a test and not just a fix
//
// The groups were wrong because nothing connected them to dispatch. Fixing the five without this
// guard leaves the next tool to drift the same way, silently, and the failure only shows up in a
// slim image nobody builds locally.
func TestToolsetGroupsCoverEveryDispatchingAsset(t *testing.T) {
	root := repoRoot(t)

	df, err := os.ReadFile(filepath.Join(root, "docker", "sandbox", "Dockerfile"))
	if err != nil {
		t.Fatalf("read sandbox Dockerfile: %v", err)
	}
	dockerfile := string(df)

	// tool -> the toolsets its install is gated on.
	gated := map[string]map[string]bool{}
	addGroups := func(tool string, groups []string) {
		if gated[tool] == nil {
			gated[tool] = map[string]bool{}
		}
		for _, g := range groups {
			gated[tool][g] = true
		}
	}
	// ts_install <asset|"a b c"> <binary> <module@version>
	for _, m := range regexp.MustCompile(`ts_install\s+(?:"([^"]+)"|(\S+))\s+(\S+)\s`).FindAllStringSubmatch(dockerfile, -1) {
		groups := m[1]
		if groups == "" {
			groups = m[2]
		}
		addGroups(m[3], strings.Fields(groups))
	}
	// { ts_want X && PKGS="$PKGS a b" }  /  { ts_want_any "x y" && PKGS="$PKGS a b" }
	pkgLine := regexp.MustCompile(`ts_want(?:_any)?\s+(?:"([^"]+)"|(\S+))\s*&&\s*PKGS="\$PKGS ([^"]+)"`)
	for _, m := range pkgLine.FindAllStringSubmatch(dockerfile, -1) {
		groups := m[1]
		if groups == "" {
			groups = m[2]
		}
		for _, pkg := range strings.Fields(m[3]) {
			addGroups(strings.SplitN(pkg, "==", 2)[0], strings.Fields(groups))
		}
	}
	if len(gated) < 15 {
		t.Fatalf("only parsed %d gated tools out of the Dockerfile — the gating syntax has changed and "+
			"this guard is no longer reading it, which is worse than not having it", len(gated))
	}

	// Which assets actually dispatch each tool, read from the handlers.
	assetDir := filepath.Join(root, "internal", "asset")
	entries, err := os.ReadDir(assetDir)
	if err != nil {
		t.Fatal(err)
	}
	var assets []string
	sources := map[string]string{}
	for _, e := range entries {
		// argcontract and common are shared helpers, not assets.
		if !e.IsDir() || e.Name() == "argcontract" || e.Name() == "common" {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(assetDir, e.Name(), "*.go"))
		var buf strings.Builder
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err == nil {
				buf.Write(b)
			}
		}
		assets = append(assets, e.Name())
		sources[e.Name()] = buf.String()
	}
	if len(assets) < 7 {
		t.Fatalf("found only %d asset handlers — this guard has stopped seeing its subject", len(assets))
	}

	var problems []string
	for tool, groups := range gated {
		for _, a := range assets {
			if !strings.Contains(sources[a], `"`+tool+`"`) {
				continue // this asset does not dispatch it
			}
			if !groups[a] {
				problems = append(problems, tool+": dispatched by "+a+
					", installed only for ["+strings.Join(sortedKeys(groups), " ")+"]")
			}
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("%d tool(s) are gated on a toolset that does not include an asset dispatching them:\n  %s\n\n"+
			"The slim image for that asset would ship the tool as a 127 stub, so the scan degrades and the "+
			"capability is silently gone. Widen the gate in docker/sandbox/Dockerfile — ts_install takes a "+
			"quoted space-separated asset list, and ts_want_any covers the PKGS lines.",
			len(problems), strings.Join(problems, "\n  "))
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
