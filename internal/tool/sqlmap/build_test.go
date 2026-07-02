package sqlmap

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// hasFlagVal asserts cli contains `flag` immediately followed by `val`.
func hasFlagVal(cli []string, flag, val string) bool {
	for i := 0; i < len(cli)-1; i++ {
		if cli[i] == flag && cli[i+1] == val {
			return true
		}
	}
	return false
}

func hasFlag(cli []string, flag string) bool {
	for _, a := range cli {
		if a == flag {
			return true
		}
	}
	return false
}

// TestBuildCLI_AnchorDefaults: the anchor path (target only) keeps the fast BEU defaults and sets
// NONE of the extraction flags — no behavior change for the L1 fan-out.
func TestBuildCLI_AnchorDefaults(t *testing.T) {
	cli, target, err := buildCLI(tool.Args{"target": "http://t/x?id=1"})
	if err != nil {
		t.Fatalf("buildCLI: %v", err)
	}
	if target != "http://t/x?id=1" {
		t.Errorf("target = %q", target)
	}
	if !hasFlagVal(cli, "--technique", "BEU") || !hasFlag(cli, "--batch") || !hasFlag(cli, "--smart") {
		t.Errorf("anchor defaults missing (want BEU+batch+smart): %v", cli)
	}
	for _, f := range []string{"--dump", "-p", "--prefix", "--suffix", "--string", "-T", "-D", "--file-read"} {
		if hasFlag(cli, f) {
			t.Errorf("anchor path must not set extraction flag %s: %v", f, cli)
		}
	}
}

// TestBuildCLI_ExtractionArgs: the dispatch_oss / replay extraction args each map to sqlmap's own
// flag, verbatim — the boolean-blind DUMP a detect-only wrapper couldn't express.
func TestBuildCLI_ExtractionArgs(t *testing.T) {
	cli, _, err := buildCLI(tool.Args{
		"target": "http://t/index.php", "data": "username=admin&password=x&submit=1",
		"param": "username", "prefix": "'", "suffix": "-- -", "string": "password",
		"dbms": "mysql", "db": "payroll_db", "table": "users", "column": "password", "dump": true,
	})
	if err != nil {
		t.Fatalf("buildCLI: %v", err)
	}
	for _, fv := range [][2]string{
		{"-p", "username"}, {"--prefix", "'"}, {"--suffix", "-- -"}, {"--string", "password"},
		{"--dbms", "mysql"}, {"-D", "payroll_db"}, {"-T", "users"}, {"-C", "password"},
		{"--data", "username=admin&password=x&submit=1"},
	} {
		if !hasFlagVal(cli, fv[0], fv[1]) {
			t.Errorf("missing %s %s in %v", fv[0], fv[1], cli)
		}
	}
	if !hasFlag(cli, "--dump") {
		t.Errorf("dump:true should add --dump: %v", cli)
	}
	// Extraction mode must DROP --smart (it heuristic-skips a subtle boolean oracle the caller
	// has already identified — the exact bug the live XBEN-029 validation surfaced).
	if hasFlag(cli, "--smart") {
		t.Errorf("extraction mode must not set --smart (heuristic-skips a known-injectable param): %v", cli)
	}
}

// TestBuildCLI_FileRead + dump accepts the JSON-string "true" (dispatch args arrive as strings).
func TestBuildCLI_FileReadAndStringBool(t *testing.T) {
	cli, _, err := buildCLI(tool.Args{"target": "http://t/", "file_read": "/FLAG.txt", "dump": "true"})
	if err != nil {
		t.Fatalf("buildCLI: %v", err)
	}
	if !hasFlagVal(cli, "--file-read", "/FLAG.txt") {
		t.Errorf("file_read not wired: %v", cli)
	}
	if !hasFlag(cli, "--dump") {
		t.Errorf(`dump:"true" (string) should add --dump: %v`, cli)
	}
}

func TestBuildCLI_MissingTarget(t *testing.T) {
	if _, _, err := buildCLI(tool.Args{"dump": true}); err == nil {
		t.Error("missing target should error")
	}
}

func TestTruthy(t *testing.T) {
	for _, v := range []any{true, "true", "1", "yes", "Y"} {
		if !truthy(v) {
			t.Errorf("truthy(%v) should be true", v)
		}
	}
	for _, v := range []any{false, "", "false", "0", "no", nil, 3} {
		if truthy(v) {
			t.Errorf("truthy(%v) should be false", v)
		}
	}
}

// TestKnownArgs_CoversExtraction: the arg-contract CI test (§5.2 C4) gates on KnownArgs — the new
// extraction keys must be declared or a dispatcher passing them is a build failure.
func TestKnownArgs_CoversExtraction(t *testing.T) {
	known := strings.Join(New().KnownArgs(), ",")
	for _, k := range []string{"param", "prefix", "suffix", "string", "dbms", "db", "table", "column", "file_read", "dump"} {
		if !strings.Contains(known, k) {
			t.Errorf("KnownArgs missing extraction key %q", k)
		}
	}
}
