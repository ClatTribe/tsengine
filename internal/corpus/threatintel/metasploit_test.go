package threatintel

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// modern Metasploit metadata: references as a flat list of prefixed strings (the current shape).
const msfFlat = `{
  "exploit/windows/smb/ms17_010_eternalblue": {
    "fullname": "exploit/windows/smb/ms17_010_eternalblue",
    "type": "exploit",
    "references": ["CVE-2017-0143", "CVE-2017-0144", "MSB-MS17-010", "URL-https://example.com"]
  },
  "auxiliary/scanner/smb/smb_ms17_010": {
    "fullname": "auxiliary/scanner/smb/smb_ms17_010",
    "type": "auxiliary",
    "references": ["CVE-2017-0144", "BID-96703"]
  },
  "exploit/multi/http/no_cve_module": {
    "fullname": "exploit/multi/http/no_cve_module",
    "type": "exploit",
    "references": ["URL-https://example.com/advisory", "OSVDB-12345"]
  }
}`

// legacy Metasploit shape: references as [type, value] pairs.
const msfPairs = `{
  "exploit/linux/http/legacy": {
    "fullname": "exploit/linux/http/legacy",
    "type": "exploit",
    "references": [["CVE", "2021-44228"], ["URL", "https://logging.apache.org"]]
  }
}`

func TestParseMetasploit_FlatStrings(t *testing.T) {
	got, err := ParseMetasploit(strings.NewReader(msfFlat))
	if err != nil {
		t.Fatal(err)
	}
	// CVE-2017-0144 is referenced by BOTH modules → two deduped refs
	refs := got["CVE-2017-0144"]
	sort.Strings(refs)
	want := []string{
		"metasploit:auxiliary/scanner/smb/smb_ms17_010",
		"metasploit:exploit/windows/smb/ms17_010_eternalblue",
	}
	if strings.Join(refs, "|") != strings.Join(want, "|") {
		t.Errorf("CVE-2017-0144 refs = %v, want %v", refs, want)
	}
	// CVE-2017-0143 only from the eternalblue module
	if r := got["CVE-2017-0143"]; len(r) != 1 || r[0] != "metasploit:exploit/windows/smb/ms17_010_eternalblue" {
		t.Errorf("CVE-2017-0143 refs = %v", r)
	}
	// a module with no CVE reference contributes nothing (grounded — non-CVE refs ignored)
	for cve := range got {
		if strings.Contains(cve, "OSVDB") || strings.Contains(cve, "BID") {
			t.Errorf("non-CVE identifier leaked as a key: %q", cve)
		}
	}
}

func TestParseMetasploit_PairShape(t *testing.T) {
	got, err := ParseMetasploit(strings.NewReader(msfPairs))
	if err != nil {
		t.Fatal(err)
	}
	if r := got["CVE-2021-44228"]; len(r) != 1 || r[0] != "metasploit:exploit/linux/http/legacy" {
		t.Errorf("Log4Shell msf ref = %v (want the legacy module)", r)
	}
}

func TestParseMetasploit_Malformed(t *testing.T) {
	if _, err := ParseMetasploit(strings.NewReader("not json")); err == nil {
		t.Error("malformed metadata must error (best-effort caller swallows it)")
	}
}

func TestMergeExploitRefs_Unions(t *testing.T) {
	edb := map[string][]string{"CVE-2017-0144": {"exploitdb:EDB-42315"}}
	msf := map[string][]string{
		"CVE-2017-0144": {"metasploit:exploit/windows/smb/ms17_010_eternalblue"},
		"CVE-2021-44228": {"metasploit:exploit/linux/http/legacy"},
	}
	merged := mergeExploitRefs(edb, msf)
	got := merged["CVE-2017-0144"]
	sort.Strings(got)
	if strings.Join(got, "|") != "exploitdb:EDB-42315|metasploit:exploit/windows/smb/ms17_010_eternalblue" {
		t.Errorf("merged CVE-2017-0144 = %v (want both overlays unioned)", got)
	}
	if len(merged["CVE-2021-44228"]) != 1 {
		t.Errorf("msf-only CVE should carry through merge, got %v", merged["CVE-2021-44228"])
	}
	// merging the same set again must not duplicate
	merged = mergeExploitRefs(merged, msf)
	if len(merged["CVE-2017-0144"]) != 2 {
		t.Errorf("re-merge must dedup, got %v", merged["CVE-2017-0144"])
	}
}

// TestBuild_ListsMetasploitSource: when the merged exploit set contains msf refs, the manifest lists
// MetasploitURL as a source — honest provenance for the pinned corpus (§10).
func TestBuild_ListsMetasploitSource(t *testing.T) {
	exploits := map[string][]string{
		"CVE-2017-0144": {"exploitdb:EDB-42315", "metasploit:exploit/windows/smb/ms17_010_eternalblue"},
	}
	_, m := Build(nil, time.Time{}, "test", nil, time.Time{}, exploits, nil)
	hasEDB, hasMSF := false, false
	for _, s := range m.Sources {
		if s == ExploitDBURL {
			hasEDB = true
		}
		if s == MetasploitURL {
			hasMSF = true
		}
	}
	if !hasEDB || !hasMSF {
		t.Errorf("manifest sources must list both exploit overlays, got %v", m.Sources)
	}
	if m.ExploitCount != 1 {
		t.Errorf("ExploitCount = %d, want 1", m.ExploitCount)
	}
	_ = types.KEVStatus{} // keep the types import (parity with sibling tests)
}
