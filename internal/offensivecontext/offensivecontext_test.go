package offensivecontext

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestResolver_Grounded: the shared resolver renders a record ONLY for a finding that names a CVE with
// a real record — a non-CVE finding and a CVE with no record both yield "" (§10: input never
// fabricates itself). This is the ONE resolver both agents read, so this is the anti-drift guard.
func TestResolver_Grounded(t *testing.T) {
	recs := map[string]threatintel.ExploitRecord{
		"CVE-2021-44228": {
			CVE: "CVE-2021-44228", Source: "nuclei", Class: "rce",
			Probes: []threatintel.ExploitProbe{{Method: "POST", Path: "/", Body: "${jndi:ldap://{{canary}}}"}},
		},
	}
	r := Resolver(recs)

	// CVE with a record → rendered skeleton
	hit := types.Finding{RuleID: "nuclei::CVE-2021-44228"}
	if out := r(hit); !strings.Contains(out, "jndi") {
		t.Fatalf("CVE-bearing finding must render its skeleton, got %q", out)
	}
	// CVE with NO record → empty
	if out := r(types.Finding{RuleID: "nuclei::CVE-2020-0001"}); out != "" {
		t.Fatalf("CVE without a record must be empty, got %q", out)
	}
	// non-CVE finding → empty
	if out := r(types.Finding{RuleID: "zap::reflected-xss"}); out != "" {
		t.Fatalf("non-CVE finding must be empty, got %q", out)
	}
	// empty record set → resolver is non-nil and returns "" (installable unconditionally)
	if Resolver(nil)(hit) != "" {
		t.Fatal("nil record set must yield an empty (non-panicking) resolver")
	}
}

// TestLoad_AbsentSidecar: a dir with no sidecar returns ok=false (the honest no-intel path), never a
// resolver that pretends.
func TestLoad_AbsentSidecar(t *testing.T) {
	if _, ok := Load(t.TempDir()); ok {
		t.Fatal("absent sidecar must return ok=false")
	}
}
