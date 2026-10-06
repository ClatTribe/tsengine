package deepsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
)

const testKey = "sk-test-SECRET-key-value-1234567890"

// fakeDeepsec mimics deepsec's on-disk contract: scan writes one FileRecord per candidate file with
// status "pending"; each process call reviews up to --limit pending files, recording a cost and,
// for files named vuln*, a finding.
type fakeDeepsec struct {
	files       int
	costPerFile float64
	failOnWave  int // 1-based; 0 = never
	stall       bool
	waves       int
	envs        [][]string
	argv        [][]string
}

func (f *fakeDeepsec) run(_ context.Context, dir string, env []string, args ...string) ([]byte, error) {
	f.envs = append(f.envs, env)
	f.argv = append(f.argv, args)
	root := filepath.Join(dir, "data", projectID, "files")
	switch args[0] {
	case "scan":
		if err := os.MkdirAll(root, 0o755); err != nil {
			return nil, err
		}
		for i := 0; i < f.files; i++ {
			name := fmt.Sprintf("file%02d.ts", i)
			if i%3 == 0 {
				name = fmt.Sprintf("vuln%02d.ts", i)
			}
			rec := map[string]any{"filePath": "src/" + name, "status": "pending",
				"candidates": []any{map[string]any{"slug": "sql-injection"}}, "findings": []any{}, "analysisHistory": []any{}}
			b, _ := json.Marshal(rec)
			if err := os.WriteFile(filepath.Join(root, name+".json"), b, 0o644); err != nil {
				return nil, err
			}
		}
		return []byte("scan complete"), nil
	case "process":
		f.waves++
		if f.failOnWave == f.waves {
			return []byte("1 batch(es) errored — exiting 1"), &exec.ExitError{}
		}
		if f.stall {
			return nil, nil
		}
		limit := 0
		for i, a := range args {
			if a == "--limit" {
				limit, _ = strconv.Atoi(args[i+1])
			}
		}
		entries, _ := os.ReadDir(root)
		done := 0
		for _, e := range entries {
			if done == limit {
				break
			}
			p := filepath.Join(root, e.Name())
			var rec map[string]any
			b, _ := os.ReadFile(p)
			_ = json.Unmarshal(b, &rec)
			if rec["status"] != "pending" {
				continue
			}
			rec["status"] = "analyzed"
			rec["analysisHistory"] = []any{map[string]any{"costUsd": f.costPerFile, "model": "gpt-5.5"}}
			if strings.HasPrefix(e.Name(), "vuln") {
				rec["findings"] = []any{map[string]any{"severity": "CRITICAL", "vulnSlug": "sql-injection",
					"title": "SQL built from a request parameter", "description": "d", "recommendation": "use parameters",
					"lineNumbers": []int{7, 9}, "confidence": "high", "findingId": "f-" + e.Name()}}
			}
			b, _ = json.Marshal(rec)
			_ = os.WriteFile(p, b, 0o644)
			done++
		}
		return []byte("Processing complete"), nil
	}
	return nil, errors.New("unexpected command " + args[0])
}

func newFake(f *fakeDeepsec) *Deepsec {
	return &Deepsec{Workspace: "/nonexistent-template", run: f.run}
}

func args(maxCost any) tool.Args {
	return tool.Args{"target": "/workspace", "_api_key": testKey, "max_cost_usd": maxCost}
}

func TestRun_CompleteReviewEmitsFindingsAndNoCoverageNote(t *testing.T) {
	f := &fakeDeepsec{files: 7, costPerFile: 0.10}
	res, err := newFake(f).Run(context.Background(), args(50.0))
	if err != nil {
		t.Fatal(err)
	}
	out := res.Output.(Output)
	if out.StoppedReason != "complete" || out.PendingFiles != 0 || out.ReviewedFiles != 7 {
		t.Fatalf("want a complete review of 7, got %+v", out)
	}
	for _, fd := range res.Findings {
		if strings.HasPrefix(fd.RuleID, asset.CoverageRulePrefix) {
			t.Fatal("a COMPLETE review must declare no coverage gap")
		}
	}
	if len(res.Findings) != 3 { // vuln00, vuln03, vuln06
		t.Fatalf("want 3 findings, got %d", len(res.Findings))
	}
	fd := res.Findings[0]
	if fd.RuleID != "deepsec::sql-injection" || fd.Severity != "critical" || len(fd.CWE) != 1 || fd.CWE[0] != "CWE-89" {
		t.Fatalf("mapping wrong: %+v", fd)
	}
	if fd.Endpoint != "src/vuln00.ts:7" {
		t.Fatalf("endpoint should cite file:first-line, got %q", fd.Endpoint)
	}
}

// The cap is enforced between waves; a review that stops on budget says how much it did not cover.
func TestRun_BudgetStopsAndDeclaresTheGap(t *testing.T) {
	f := &fakeDeepsec{files: 20, costPerFile: 0.25} // a wave of 5 costs $1.25
	res, err := newFake(f).Run(context.Background(), args(2.0))
	if err != nil {
		t.Fatal(err)
	}
	out := res.Output.(Output)
	if out.StoppedReason != "budget" {
		t.Fatalf("want stop on budget, got %+v", out)
	}
	// Overshoot is bounded by one wave: two waves ($2.50) ran, a third did not.
	if f.waves != 2 || out.CostUSD > 2.0+float64(waveSize)*0.25 {
		t.Fatalf("waves=%d cost=%.2f — the cap must stop the run within one wave", f.waves, out.CostUSD)
	}
	last := res.Findings[len(res.Findings)-1]
	if !strings.HasPrefix(last.RuleID, asset.CoverageRulePrefix) || last.Severity != "info" {
		t.Fatalf("a capped review must end with an informational coverage note, got %+v", last)
	}
	if !strings.Contains(last.Title, "10 of 20") {
		t.Fatalf("the note must say how much was not reviewed, got %q", last.Title)
	}
}

func TestRun_LaterWaveFailureKeepsFindingsAndDeclaresTheGap(t *testing.T) {
	f := &fakeDeepsec{files: 12, costPerFile: 0.1, failOnWave: 2}
	res, err := newFake(f).Run(context.Background(), args(50.0))
	if err != nil {
		t.Fatalf("a failure after reviewed waves must not discard what was reviewed: %v", err)
	}
	out := res.Output.(Output)
	if out.StoppedReason != "wave_failed" || out.PendingFiles != 7 {
		t.Fatalf("want wave_failed with 7 unreviewed, got %+v", out)
	}
}

// Nothing reviewed and the agent failed: the tool did not look, and must not return an empty list.
func TestRun_FirstWaveFailureIsAnError(t *testing.T) {
	f := &fakeDeepsec{files: 4, costPerFile: 0.1, failOnWave: 1}
	if _, err := newFake(f).Run(context.Background(), args(50.0)); err == nil {
		t.Fatal("a review that reviewed nothing must fail loudly, not read as clean")
	}
}

func TestRun_StallDoesNotLoopForever(t *testing.T) {
	f := &fakeDeepsec{files: 4, costPerFile: 0.1, stall: true}
	res, err := newFake(f).Run(context.Background(), args(50.0))
	if err != nil {
		t.Fatal(err)
	}
	if f.waves != 1 || res.Output.(Output).StoppedReason != "wave_failed" {
		t.Fatalf("a wave that reviews nothing must stop the run, waves=%d", f.waves)
	}
}

func TestRun_RefusesWithoutKeyOrCap(t *testing.T) {
	f := &fakeDeepsec{files: 1}
	d := newFake(f)
	for name, a := range map[string]tool.Args{
		"no key":     {"target": "/w", "max_cost_usd": 5.0},
		"no cap":     {"target": "/w", "_api_key": testKey},
		"zero cap":   {"target": "/w", "_api_key": testKey, "max_cost_usd": 0.0},
		"absurd cap": {"target": "/w", "_api_key": testKey, "max_cost_usd": 5000.0},
		"no target":  {"_api_key": testKey, "max_cost_usd": 5.0},
	} {
		if _, err := d.Run(context.Background(), a); err == nil {
			t.Errorf("%s: must refuse", name)
		}
	}
	if len(f.argv) != 0 {
		t.Fatal("a refused run must not invoke deepsec at all")
	}
}

// The child sees PATH, a throwaway HOME/CODEX_HOME and the one key — nothing inherited. Run on a
// developer machine, deepsec otherwise used the machine's codex login and billed it.
func TestRun_ChildEnvironmentIsBuiltFromNothing(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "inherited-cloud-secret")
	t.Setenv("AI_GATEWAY_API_KEY", "inherited-gateway")
	t.Setenv("OPENAI_API_KEY", "ambient-openai-key")
	f := &fakeDeepsec{files: 2, costPerFile: 0.1}
	if _, err := newFake(f).Run(context.Background(), args(5.0)); err != nil {
		t.Fatal(err)
	}
	for _, env := range f.envs {
		joined := strings.Join(env, "\n")
		for _, leak := range []string{"inherited-cloud-secret", "inherited-gateway", "ambient-openai-key", "AWS_", "VERCEL"} {
			if strings.Contains(joined, leak) {
				t.Fatalf("child environment inherited %q:\n%s", leak, joined)
			}
		}
		if !strings.Contains(joined, "OPENAI_API_KEY="+testKey) || !strings.Contains(joined, "CODEX_HOME=") {
			t.Fatalf("child must get exactly the provided key and an isolated CODEX_HOME:\n%s", joined)
		}
	}
}

func TestRun_KeyNeverAppearsInFindingsOrOutput(t *testing.T) {
	f := &fakeDeepsec{files: 10, costPerFile: 0.5}
	res, err := newFake(f).Run(context.Background(), args(1.0))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), testKey) {
		t.Fatal("the model key leaked into the result")
	}
	for _, a := range f.argv {
		if strings.Contains(strings.Join(a, " "), testKey) {
			t.Fatal("the model key was passed on the command line, where ps can read it")
		}
	}
	// And an error string is scrubbed too.
	if got := detail(errors.New("boom"), []byte("auth failed for "+testKey), testKey); strings.Contains(got, testKey) {
		t.Fatalf("detail leaked the key: %q", got)
	}
}

func TestCoveragePrefixMatchesTheContract(t *testing.T) {
	if coverageRulePrefix != asset.CoverageRulePrefix {
		t.Fatalf("coverageRulePrefix %q drifted from asset.CoverageRulePrefix %q — the gap would be counted as a finding",
			coverageRulePrefix, asset.CoverageRulePrefix)
	}
}

func TestNormSeverityNeverInflates(t *testing.T) {
	for in, want := range map[string]string{"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
		"LOW": "low", "BUG": "info", "": "info", "weird": "info"} {
		if got := string(normSeverity(in)); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
