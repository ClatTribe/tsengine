package tool

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// swallowing is every wrapper that still routes its exec error through DidNotRun ALONE — i.e. it
// treats every non-zero exit as the scanner talking, without declaring which exits actually mean
// "found something".
//
// # Why this list exists instead of a blanket fix
//
// trivy and grype were converted because their failure was MEASURED: neither is passed --exit-code
// or --fail-on, so a non-zero exit is unambiguously an error, and both were reporting a failed scan
// as a clean one. The rest are NOT obviously the same. semgrep, gitleaks and hadolint genuinely exit
// 1 to mean "found something"; naabu exits non-zero when it finds no open ports. Converting them on
// the assumption that trivy's semantics generalise would trade a false all-clear for a permanently
// degraded pass — in which incidents never resolve, no fix is ever confirmed, and every control gap
// stays open. That is not the safer direction, it is a different bug.
//
// So this list is the honest remainder: the surface that has NOT been checked, recorded so it stays
// countable. A wrapper leaves the list by having someone determine its real exit semantics from the
// flags ITS call site passes and calling tool.Failed with them.
//
// THE RATCHET IS THE POINT: a NEW wrapper may not join this list. New code declares its contract.
// mustDeclare is the MEASURED-ERROR class (ADR 0031 D1): wrappers whose call site passes no
// findings-exit flag, so a non-zero exit is unambiguously an error and swallowing it reports a
// failed scan as clean — the trivy defect, and for prowler/scoutsuite the way a bad-credential
// cloud scan rendered as an all-clear estate. These MUST appear in the declaring set; the ratchet
// previously could not see wrappers that used NEITHER symbol, which is exactly how the cloud pair
// stayed invisible.
var mustDeclare = map[string]bool{
	"trivy": true, "grype": true, "prowler": true, "scoutsuite": true,
}

var swallowing = map[string]bool{
	"amass": true, "apkid": true, "bandit": true, "checkdmarc": true, "checkov": true,
	"cloudfox": true, "codeql": true, "dalfox": true, "dnstwist": true, "dockle": true,
	"gitleaks": true, "gosec": true, "govulncheck": true, "hadolint": true,
	"httpx": true, "hydra": true, "inql": true, "katana": true, "kiterunner": true,
	"mobsfscan": true, "modelscan": true, "naabu": true, "nikto": true, "nmap": true,
	"nuclei": true, "osvscanner": true, "padbuster": true, "semgrep": true, "sqlmap": true,
	"subfinder": true, "syft": true, "trufflehog": true, "wpscan": true,
}

func TestExitContract_NoNewWrapperMaySwallowSilently(t *testing.T) {
	dirs, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read wrapper dirs: %v — if the tool packages moved, move this guard with them "+
			"rather than letting it stop seeing its subject", err)
	}

	var swallows, declares []string
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		var usesDidNotRun, usesFailed bool
		files, _ := filepath.Glob(filepath.Join(d.Name(), "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			src := string(b)
			if strings.Contains(src, "tool.Failed(") {
				usesFailed = true
			}
			if strings.Contains(src, "tool.DidNotRun(") {
				usesDidNotRun = true
			}
		}
		switch {
		case usesFailed:
			declares = append(declares, d.Name())
		case usesDidNotRun:
			swallows = append(swallows, d.Name())
		}
	}
	sort.Strings(swallows)

	// A guard whose subject vanished must fail, not pass quietly (§14.2 rule 6). If the scan found
	// almost nothing, the patterns have stopped matching and this reports a clean bill of health for
	// code nobody inspected.
	if len(swallows)+len(declares) < 20 {
		t.Fatalf("only classified %d wrappers (%d swallow, %d declare) — this guard has stopped "+
			"seeing the tool packages", len(swallows)+len(declares), len(swallows), len(declares))
	}

	for _, name := range swallows {
		if !swallowing[name] {
			t.Errorf("%s treats every non-zero exit as a findings-signal and is not on the reviewed "+
				"list.\n\nDetermine what a non-zero exit really means for the flags %s's call site "+
				"passes, then call tool.Failed with the exits that mean \"found something\" (none, for "+
				"most tools). A wrapper that guesses reports either a failed scan as clean — the trivy "+
				"defect — or a successful scan as degraded.", name, name)
		}
	}
	for name := range mustDeclare {
		if !containsStr(declares, name) {
			t.Errorf("%s is on the measured-error list (no findings-exit flag at its call site) but does "+
				"not call tool.Failed — it either swallows its exec error or uses neither contract "+
				"symbol. A scanner whose non-zero exit means ERROR must fail loudly: a swallowed error "+
				"is how a bad-credential cloud scan reported a clean estate.", name)
		}
	}
	for name := range swallowing {
		if !containsStr(swallows, name) {
			t.Errorf("%s is on the swallowing list but no longer swallows. If it was converted, "+
				"DELETE its entry — a remainder list that keeps fixed entries overstates the work left "+
				"and stops being read.", name)
		}
	}
	t.Logf("exit contracts: %d declared (%v), %d still swallowing", len(declares), declares, len(swallows))
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
