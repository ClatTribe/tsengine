package padbuster

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func hasSeq(cli []string, a, b string) bool {
	for i := 0; i < len(cli)-1; i++ {
		if cli[i] == a && cli[i+1] == b {
			return true
		}
	}
	return false
}

func has(cli []string, a string) bool {
	for _, x := range cli {
		if x == a {
			return true
		}
	}
	return false
}

// TestBuildCLI_Positional: URL, sample, blocksize are the first three positional args (padbuster's
// contract), default block 16 (AES), non-interactive appended.
func TestBuildCLI_Positional(t *testing.T) {
	cli, err := buildCLI(tool.Args{"target": "http://t/verify", "sample": "AABBCC"})
	if err != nil {
		t.Fatalf("buildCLI: %v", err)
	}
	if len(cli) < 3 || cli[0] != "http://t/verify" || cli[1] != "AABBCC" || cli[2] != "16" {
		t.Errorf("positional args wrong (want url sample 16): %v", cli)
	}
	// -noninteractive is NOT a real padbuster flag (verified against GDSSecurity/padBuster.pl) — the
	// wrapper must never emit it (it would abort the run).
	if has(cli, "-noninteractive") {
		t.Errorf("must NOT emit the non-existent -noninteractive flag: %v", cli)
	}
}

// TestBuildCLI_ForgeAndOracle: forge (plaintext) + the oracle signature (error) + cookie carrier all
// map to padbuster's flags — the "encrypt arbitrary plaintext" path that forges a valid cookie.
func TestBuildCLI_ForgeAndOracle(t *testing.T) {
	cli, err := buildCLI(tool.Args{
		"target": "http://t/", "sample": "Zm9v", "block_size": "16",
		"cookies": "auth=Zm9v", "error": "Padding", "encoding": "0",
		"plaintext": "admin=1", "no_iv": true,
	})
	if err != nil {
		t.Fatalf("buildCLI: %v", err)
	}
	for _, fv := range [][2]string{
		{"-cookies", "auth=Zm9v"}, {"-error", "Padding"}, {"-encoding", "0"}, {"-plaintext", "admin=1"},
	} {
		if !hasSeq(cli, fv[0], fv[1]) {
			t.Errorf("missing %s %s: %v", fv[0], fv[1], cli)
		}
	}
	if !has(cli, "-noiv") {
		t.Errorf("no_iv:true should add -noiv: %v", cli)
	}
	if cli[2] != "16" {
		t.Errorf("block_size not honored: %v", cli)
	}
}

// TestBuildCLI_NoEncode: -noencode is REQUIRED for a base64-cookie oracle (proven live on XBEN-101 —
// without it padbuster percent-encodes the base64 and every response looks like invalid padding).
func TestBuildCLI_NoEncode(t *testing.T) {
	cli, err := buildCLI(tool.Args{"target": "http://t/", "sample": "Zm9v", "no_encode": true})
	if err != nil {
		t.Fatalf("buildCLI: %v", err)
	}
	if !has(cli, "-noencode") {
		t.Errorf("no_encode:true should add -noencode: %v", cli)
	}
	// default (absent) must NOT add it — a hex/URL-param oracle wants padbuster's default encoding.
	cli2, _ := buildCLI(tool.Args{"target": "http://t/", "sample": "Zm9v"})
	if has(cli2, "-noencode") {
		t.Errorf("no_encode absent must not add -noencode: %v", cli2)
	}
}

func TestBuildCLI_Required(t *testing.T) {
	if _, err := buildCLI(tool.Args{"target": "http://t/"}); err == nil {
		t.Error("missing sample should error")
	}
	if _, err := buildCLI(tool.Args{"sample": "x"}); err == nil {
		t.Error("missing target should error")
	}
}

func TestKnownArgs(t *testing.T) {
	known := strings.Join(New().KnownArgs(), ",")
	for _, k := range []string{"target", "sample", "block_size", "error", "encoding", "cookies", "plaintext", "no_iv"} {
		if !strings.Contains(known, k) {
			t.Errorf("KnownArgs missing %q", k)
		}
	}
}

func TestRegisteredAndSandboxed(t *testing.T) {
	p := New()
	if !p.SandboxExecution() {
		t.Error("padbuster must run in the sandbox")
	}
	if p.Name() != "padbuster" {
		t.Errorf("name = %q", p.Name())
	}
}
