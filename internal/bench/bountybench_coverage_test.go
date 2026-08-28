package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoveredCWEsNameARealDetector guards the ONE number in the BountyBench inventory that must
// never be gamed: the honest denominator ("21 of 46 in a class we cover"). Its whole value is that
// it under-claims — it tells us what we CANNOT speak to, ranked by someone else's corpus.
//
// The failure mode is silent and tempting: add a CWE to coveredCWEs and the covered count rises
// with no detector behind it, turning a build backlog into a flattering statistic. So every entry
// must NAME its detector, and that name must correspond to something that actually exists in this
// tree. Measured when this was written: CWE-601 was added because internal/pentest/active.go really
// ships an `openRedirect` playbook with a canary-Location predicate; CWE-400 was REFUSED because its
// only matches were comments about our own rate limiting.
func TestCoveredCWEsNameARealDetector(t *testing.T) {
	if len(coveredCWEs) == 0 {
		t.Fatal("coveredCWEs is empty — this guard cannot see its subject")
	}
	// Tokens that name a real, checkable capability in this repo.
	known := []string{
		"semgrep", "nuclei", "sqlmap", "dalfox", "apiauthz", "bola_probe", "privesc_probe",
		"trivy", "grype", "gitleaks", "codeql", "openRedirect", "pentest",
	}
	for cwe, desc := range coveredCWEs {
		if strings.TrimSpace(desc) == "" {
			t.Errorf("%s: covered with no detector named — a class counts only if a real detector exists", cwe)
			continue
		}
		named := false
		for _, k := range known {
			if strings.Contains(strings.ToLower(desc), strings.ToLower(k)) {
				named = true
				break
			}
		}
		if !named {
			t.Errorf("%s: %q names no recognised detector. Either name the real one or REMOVE the class —\n"+
				"inflating the covered count turns an honest backlog into a flattering statistic.", cwe, desc)
		}
	}
}

// TestOpenRedirectDetectorActuallyExists pins the specific claim just added, by looking for the
// playbook in the source rather than trusting the map's own description. If the playbook is ever
// removed, the coverage claim must fail with it.
func TestOpenRedirectDetectorActuallyExists(t *testing.T) {
	if _, ok := coveredCWEs["CWE-601"]; !ok {
		t.Skip("CWE-601 not claimed as covered — nothing to verify")
	}
	root := filepath.Join("..", "pentest", "active.go")
	b, err := os.ReadFile(root)
	if err != nil {
		t.Fatalf("cannot read %s: %v — the guard cannot see its subject", root, err)
	}
	src := string(b)
	if !strings.Contains(src, "func openRedirect(") {
		t.Error("CWE-601 is claimed as covered but internal/pentest/active.go has no openRedirect playbook")
	}
	if !strings.Contains(src, "CWE-601") {
		t.Error("the openRedirect playbook no longer matches CWE-601 by name, so the claim is stale")
	}
}
