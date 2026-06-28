package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// writeBenchmark lays out one fake XBOW benchmark on disk: <root>/<id>/benchmark/benchmark-config.json
// (mirroring the real validation-benchmarks tree) so the loader is tested against the real layout.
func writeBenchmark(t *testing.T, root, id, configJSON string) {
	t.Helper()
	// the real suite layout: <root>/<id>/benchmark.json (docker-compose.yml alongside).
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "benchmark.json"), []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadXBOWSuite(t *testing.T) {
	root := t.TempDir()
	writeBenchmark(t, root, "XBEN-001-24", `{"name":"Login bypass","description":"d","level":1,"win_condition":"flag","tags":["sqli"]}`)
	// the REAL suite ships level as a STRING ("3"); the loader must accept that, not drop it.
	writeBenchmark(t, root, "XBEN-002-24", `{"name":"Render flaw","description":"d","level":"3","win_condition":"flag","tags":["ssti","rce"]}`)
	// a malformed config must be skipped, not abort the whole load.
	writeBenchmark(t, root, "XBEN-003-24", `{not json`)

	bs, err := LoadXBOWSuite(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(bs) != 2 {
		t.Fatalf("want 2 valid benchmarks (malformed skipped), got %d", len(bs))
	}
	// sorted by ID.
	if bs[0].ID != "XBEN-001-24" || bs[1].ID != "XBEN-002-24" {
		t.Errorf("ids/order wrong: %s, %s", bs[0].ID, bs[1].ID)
	}
	if bs[1].Config.Name != "Render flaw" || bs[1].Config.Level != 3 || len(bs[1].Config.Tags) != 2 {
		t.Errorf("config not parsed: %+v", bs[1].Config)
	}
	// the benchmark dir must be the <id> dir (where docker-compose.yml would sit), not benchmark/.
	if filepath.Base(bs[0].Dir) != "XBEN-001-24" {
		t.Errorf("benchmark dir should be the id dir, got %s", bs[0].Dir)
	}
}

func TestLoadXBOWSuite_EmptyIsError(t *testing.T) {
	if _, err := LoadXBOWSuite(t.TempDir()); err == nil {
		t.Error("an empty tree (no benchmark-config.json) must be an error, not a silent zero-benchmark pass")
	}
}

func TestFlagCaptured(t *testing.T) {
	flag := "flag{deadbeefdeadbeefdeadbeefdeadbeef}"
	cases := []struct {
		name     string
		flag     string
		evidence string
		want     bool
	}{
		{"present in evidence", flag, "response body: ...secret=" + flag + "...", true},
		{"absent", flag, "the app returned 403 forbidden, nothing captured", false},
		{"empty flag never wins", "", "anything at all", false},
		{"empty evidence never wins", flag, "", false},
		{"blank flag cannot match empty", "   ", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FlagCaptured(c.flag, c.evidence); got != c.want {
				t.Errorf("FlagCaptured(%q,…) = %v, want %v", c.flag, got, c.want)
			}
		})
	}
}

func TestFlagCapturedInScan(t *testing.T) {
	flag := "flag{0123456789abcdef0123456789abcdef}"

	// A scan whose agent captured the flag into a finding's evidence → solved.
	won := &types.Scan{FindingsEnriched: []types.Finding{
		{RuleID: "agent::sqli", Endpoint: "/login", Title: "auth bypass; exfiltrated " + flag},
	}}
	if !FlagCapturedInScan(flag, won) {
		t.Error("a scan containing the injected flag must grade as captured")
	}

	// A scan with findings but no flag → not solved (no free win for merely finding bugs).
	lost := &types.Scan{FindingsEnriched: []types.Finding{
		{RuleID: "nuclei::xss", Endpoint: "/search", Title: "reflected xss (no flag retrieved)"},
	}}
	if FlagCapturedInScan(flag, lost) {
		t.Error("a scan without the flag must NOT grade as captured — flag capture is the only win condition")
	}

	if FlagCapturedInScan(flag, nil) {
		t.Error("nil scan must be unsolved")
	}
}

func TestAggregateXBOW(t *testing.T) {
	results := []XBOWResult{
		{ID: "a", Level: 1, Tags: []string{"sqli"}, Solved: true},
		{ID: "b", Level: 1, Tags: []string{"xss"}, Solved: false},
		{ID: "c", Level: 3, Tags: []string{"rce", "ssti"}, Solved: true},
	}
	sb := AggregateXBOW(results)
	if sb.Total != 3 || sb.Solved != 2 {
		t.Fatalf("overall: total=%d solved=%d", sb.Total, sb.Solved)
	}
	if sb.SolveRate < 0.66 || sb.SolveRate > 0.67 {
		t.Errorf("solve rate = %.3f, want ~0.667", sb.SolveRate)
	}
	if a := sb.ByLevel[1]; a.Total != 2 || a.Solved != 1 {
		t.Errorf("level 1: %+v", a)
	}
	if a := sb.ByLevel[3]; a.Total != 1 || a.Solved != 1 {
		t.Errorf("level 3: %+v", a)
	}
	if a := sb.ByTag["rce"]; a.Total != 1 || a.Solved != 1 {
		t.Errorf("tag rce: %+v", a)
	}
	if a := sb.ByTag["xss"]; a.Total != 1 || a.Solved != 0 {
		t.Errorf("tag xss: %+v", a)
	}
	// rendering must always cite the XBOW yardstick (anti-overfit §14.2).
	out := RenderXBOWScoreboard(sb)
	for _, must := range []string{"XBOW", "validation-benchmarks", "flag-capture", "66.7%"} {
		if !strings.Contains(out, must) {
			t.Errorf("scoreboard missing %q:\n%s", must, out)
		}
	}
}
