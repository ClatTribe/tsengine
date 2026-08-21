package threatintel

import (
	"strings"
	"testing"
)

// An auxiliary module is a scanner, fuzzer or credential checker; a post module runs after
// you already have a session. Counting either as WEAPONIZED would put version detection on
// the same rung as remote code execution, which is the whole distinction this source exists
// to draw.
func TestParseMetasploit_OnlyExploitModulesCount(t *testing.T) {
	in := `{
	  "a": {"fullname":"exploit/multi/http/log4shell","type":"exploit","references":["CVE-2021-44228"]},
	  "b": {"fullname":"auxiliary/scanner/http/log4shell_scanner","type":"auxiliary","references":["CVE-2021-44228"]},
	  "c": {"fullname":"post/multi/gather/creds","type":"post","references":["CVE-2021-44228"]}
	}`
	got, err := ParseMetasploit(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	refs := got["CVE-2021-44228"]
	if len(refs) != 1 || refs[0] != "metasploit:exploit/multi/http/log4shell" {
		t.Errorf("refs = %v; want only the exploit module", refs)
	}
}

// A URL reference that happens to contain a CVE id is not the module declaring it exploits
// that CVE. Treating it as one credits a module with every CVE mentioned in a blog post it
// links to.
func TestParseMetasploit_URLReferencesAreNotCVEClaims(t *testing.T) {
	in := `{
	  "a": {"fullname":"exploit/x","type":"exploit","references":[
	     "URL-https://example.test/blog/CVE-2021-9999-explained",
	     "CVE-2021-1111"]}
	}`
	got, err := ParseMetasploit(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["CVE-2021-9999"]; ok {
		t.Error("a CVE inside a URL reference must not be claimed as exploited by the module")
	}
	if len(got["CVE-2021-1111"]) != 1 {
		t.Errorf("the real CVE reference must be kept: %v", got)
	}
}

// The corpus is diffed between refreshes. Map-order output would make every rebuild look
// like a change to every CVE a module touches, and a repeated ref would read as two weapons.
func TestParseMetasploit_RefsAreSortedAndDeduped(t *testing.T) {
	in := `{
	  "a": {"fullname":"exploit/zzz","type":"exploit","references":["CVE-2021-1111","2021-1111"]},
	  "b": {"fullname":"exploit/aaa","type":"exploit","references":["CVE-2021-1111"]}
	}`
	got, err := ParseMetasploit(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"metasploit:exploit/aaa", "metasploit:exploit/zzz"}
	refs := got["CVE-2021-1111"]
	if len(refs) != len(want) {
		t.Fatalf("refs = %v; want %v (the same CVE twice on one module is one weapon)", refs, want)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Errorf("refs[%d] = %q, want %q", i, refs[i], want[i])
		}
	}
}

// A module with no usable path is skipped rather than keyed on an empty string, which would
// collapse every such module into one ref that names nothing.
func TestParseMetasploit_ModuleWithNoPathIsSkipped(t *testing.T) {
	got, err := ParseMetasploit(strings.NewReader(`{"a":{"type":"exploit","references":["CVE-2021-1111"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a module with neither fullname nor name must be skipped, got %v", got)
	}
}

// Rank discriminates in practice rather than sitting at the top, which is what makes it
// worth carrying: EternalBlue is AVERAGE because it can crash the target, DoublePulsar RCE
// is GREAT, and the Log4Shell modules are EXCELLENT.
func TestParseMetasploitRanked_KeepsTheBestModule(t *testing.T) {
	in := `{
	  "a": {"fullname":"exploit/windows/smb/ms17_010_eternalblue","type":"exploit","rank":200,"references":["CVE-2017-0144"]},
	  "b": {"fullname":"exploit/windows/smb/smb_doublepulsar_rce","type":"exploit","rank":500,"references":["CVE-2017-0144"]}
	}`
	_, rank, err := ParseMetasploitRanked(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	// BEST, not first or average: an attacker uses the most reliable module they have, so
	// the question a defender needs answered is what the strongest weapon is. Averaging
	// would let a shaky module dilute a great one and describe the arsenal, not the threat.
	if got := RankName(rank["CVE-2017-0144"]); got != "great" {
		t.Errorf("rank = %q, want great (the better of average and great)", got)
	}
}

// An unrecognised rank stays unnamed rather than rounding to the nearest known rung —
// reporting a rank we cannot name invents the very judgement the field exists to carry.
func TestRankName_UnknownStaysEmpty(t *testing.T) {
	if got := RankName(451); got != "" {
		t.Errorf("RankName(451) = %q, want empty", got)
	}
	if got := RankName(600); got != "excellent" {
		t.Errorf("RankName(600) = %q, want excellent", got)
	}
}

// An auxiliary module contributes no rank, for the same reason it contributes no ref.
func TestParseMetasploitRanked_AuxiliaryContributesNoRank(t *testing.T) {
	in := `{"a": {"fullname":"auxiliary/scanner/x","type":"auxiliary","rank":600,"references":["CVE-2000-0001"]}}`
	refs, rank, err := ParseMetasploitRanked(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 || rank["CVE-2000-0001"] != 0 {
		t.Errorf("a scanner must contribute neither a ref nor a rank: refs=%v rank=%v", refs, rank)
	}
}
