package codesweep

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

func testRepo() codelocalize.Repo {
	return codelocalize.Repo{
		{Path: "store/users.go", Content: "package store\n" +
			"func Find(db *sql.DB, r *http.Request) {\n" +
			"\tname := r.URL.Query().Get(\"n\")\n" +
			"\tdb.Query(\"SELECT * FROM users WHERE n='\" + name + \"'\")\n" +
			"}\n"},
		{Path: "web/render.js", Content: "function show(req, res) {\n" +
			"\tconst q = req.query.q;\n" +
			"\tres.send('<div>' + q + '</div>');\n" +
			"}\n"},
		{Path: "util/math.go", Content: "package util\nfunc Add(a, b int) int { return a + b }\n"},
	}
}

// scriptLLM answers per task, keyed by the CWE+path it sees in the prompt.
type scriptLLM struct {
	mu      sync.Mutex
	answers map[string]string // "CWE|path" → raw output
	fallbk  string
	err     error
	seen    []string
}

func (s *scriptLLM) Generate(_ context.Context, prompt string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	var cwe, path string
	for _, ln := range strings.Split(prompt, "\n") {
		if strings.HasPrefix(ln, "WEAKNESS: ") {
			cwe = strings.TrimPrefix(ln, "WEAKNESS: ")
		}
		if strings.HasPrefix(ln, "FILE: ") {
			path = strings.TrimPrefix(ln, "FILE: ")
		}
	}
	k := cwe + "|" + path
	s.seen = append(s.seen, k)
	if a, ok := s.answers[k]; ok {
		return a, nil
	}
	return s.fallbk, nil
}

const notVuln = `{"vulnerable":false}`

func vuln(path string, line int, sev string) string {
	return fmt.Sprintf(`{"vulnerable":true,"severity":%q,"title":"injection","rationale":"user input reaches the sink","evidence":["%s:%d"]}`, sev, path, line)
}

// --- Plan: decomposition ---------------------------------------------------

func TestPlan_DecomposesIntoFocusedTasks(t *testing.T) {
	tasks, err := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, testRepo(), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) == 0 {
		t.Fatal("expected focused tasks from a repo with real sinks")
	}
	// Each task is ONE class against ONE file — that is the whole point.
	for _, k := range tasks {
		if k.CWE == "" || k.Path == "" {
			t.Fatalf("a task must name a class and a file: %+v", k)
		}
		if k.Path == "util/math.go" {
			t.Errorf("a clean file should not generate a task: %+v", k)
		}
	}
	// The SQLi sink must be planned.
	found := false
	for _, k := range tasks {
		if k.CWE == "CWE-89" && k.Path == "store/users.go" {
			found = true
			if len(k.SinkLines) == 0 {
				t.Error("the task should carry the sink lines localize found")
			}
		}
	}
	if !found {
		t.Errorf("expected a CWE-89 task for store/users.go, got %+v", tasks)
	}
}

func TestPlan_IsDeterministicAndCapped(t *testing.T) {
	a, _ := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, testRepo(), PlanOptions{})
	b, _ := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, testRepo(), PlanOptions{})
	if len(a) != len(b) {
		t.Fatalf("plan is not deterministic: %d vs %d", len(a), len(b))
	}
	for i := range a {
		// Task contains a []string, so compare the identity fields that define plan order.
		if a[i].CWE != b[i].CWE || a[i].Path != b[i].Path || a[i].Confidence != b[i].Confidence {
			t.Fatalf("plan order drifted at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
	capped, _ := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, testRepo(), PlanOptions{MaxTasks: 2})
	if len(capped) != 2 {
		t.Fatalf("MaxTasks must cap the plan, got %d", len(capped))
	}
	// A cap keeps the STRONGEST priors, not an arbitrary slice.
	if capped[0].Confidence < capped[len(capped)-1].Confidence {
		t.Error("a capped plan should keep the highest-confidence tasks")
	}
}

// --- Sweep: the disposer ---------------------------------------------------

func TestSweep_KeepsGroundedFindingAndDropsCleanFile(t *testing.T) {
	repo := testRepo()
	tasks := []Task{
		{CWE: "CWE-89", Path: "store/users.go", Confidence: 0.85},
		{CWE: "CWE-79", Path: "web/render.js", Confidence: 0.6},
	}
	llm := &scriptLLM{answers: map[string]string{
		"CWE-89|store/users.go": vuln("store/users.go", 4, "critical"),
		"CWE-79|web/render.js":  notVuln,
	}}
	res, err := Sweep(context.Background(), llm, repo, tasks, SweepOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ran != 2 || res.Failed != 0 || res.Refused != 0 {
		t.Fatalf("unexpected counts: %+v", res)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].Path != "store/users.go" {
		t.Fatalf("only the vulnerable file should surface: %+v", res.Candidates)
	}
	if res.Candidates[0].Evidence[0] != "store/users.go:4" {
		t.Errorf("evidence should be the verified location: %v", res.Candidates[0].Evidence)
	}
}

// THE SAFETY PROPERTY. Parallelism widens the search; it must not widen what counts as evidence.
func TestSweep_RefusesUngroundedClaims(t *testing.T) {
	repo := testRepo()
	cases := map[string]string{
		"cites another file":        `{"vulnerable":true,"severity":"high","evidence":["util/math.go:1"]}`,
		"cites past EOF":            `{"vulnerable":true,"severity":"high","evidence":["store/users.go:9999"]}`,
		"cites a file it never saw": `{"vulnerable":true,"severity":"high","evidence":["secret/keys.go:3"]}`,
		"no evidence at all":        `{"vulnerable":true,"severity":"critical","title":"trust me"}`,
		"malformed location":        `{"vulnerable":true,"severity":"high","evidence":["store/users.go"]}`,
	}
	for name, answer := range cases {
		llm := &scriptLLM{fallbk: answer}
		res, err := Sweep(context.Background(), llm, repo,
			[]Task{{CWE: "CWE-89", Path: "store/users.go"}}, SweepOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Candidates) != 0 {
			t.Errorf("%s: must be refused, got %+v", name, res.Candidates)
		}
		if res.Refused != 1 {
			t.Errorf("%s: refusal should be counted, got %+v", name, res)
		}
	}
}

// An invented severity must not become an escalation channel.
func TestSweep_NormalizesUnknownSeverity(t *testing.T) {
	llm := &scriptLLM{fallbk: `{"vulnerable":true,"severity":"CATASTROPHIC","evidence":["store/users.go:4"]}`}
	res, _ := Sweep(context.Background(), llm, testRepo(),
		[]Task{{CWE: "CWE-89", Path: "store/users.go"}}, SweepOptions{})
	if len(res.Candidates) != 1 || res.Candidates[0].Severity != "medium" {
		t.Fatalf("an invented severity should normalize to medium, got %+v", res.Candidates)
	}
}

// One broken answer must not discard the rest of the sweep.
func TestSweep_CountsFailuresWithoutLosingGoodResults(t *testing.T) {
	llm := &scriptLLM{
		answers: map[string]string{"CWE-89|store/users.go": vuln("store/users.go", 4, "high")},
		fallbk:  "I cannot help with that", // unparseable
	}
	res, err := Sweep(context.Background(), llm, testRepo(), []Task{
		{CWE: "CWE-89", Path: "store/users.go"},
		{CWE: "CWE-79", Path: "web/render.js"},
	}, SweepOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 {
		t.Errorf("the unparseable answer should be counted, got %+v", res)
	}
	if len(res.Candidates) != 1 {
		t.Errorf("the good result must survive, got %+v", res.Candidates)
	}
}

// Concurrency must not make the report non-reproducible (§10).
func TestSweep_DeterministicUnderConcurrency(t *testing.T) {
	repo := testRepo()
	tasks := []Task{
		{CWE: "CWE-89", Path: "store/users.go", Confidence: 0.9},
		{CWE: "CWE-79", Path: "web/render.js", Confidence: 0.6},
		{CWE: "CWE-94", Path: "web/render.js", Confidence: 0.5},
	}
	llm := &scriptLLM{answers: map[string]string{
		"CWE-89|store/users.go": vuln("store/users.go", 4, "high"),
		"CWE-79|web/render.js":  vuln("web/render.js", 3, "high"),
		"CWE-94|web/render.js":  vuln("web/render.js", 2, "low"),
	}}
	var first string
	for i := 0; i < 5; i++ {
		res, _ := Sweep(context.Background(), llm, repo, tasks, SweepOptions{Concurrency: 3})
		var b strings.Builder
		for _, c := range res.Candidates {
			fmt.Fprintf(&b, "%s|%s|%s;", c.Severity, c.Path, c.CWE)
		}
		if i == 0 {
			first = b.String()
		} else if b.String() != first {
			t.Fatalf("run %d differed:\n %s\n %s", i, first, b.String())
		}
	}
	if !strings.HasPrefix(first, "high|") {
		t.Errorf("highest severity must lead: %s", first)
	}
}

// The same weakness in the same file found twice is ONE weakness.
func TestDedupe_CollapsesSamePathAndClassKeepingStrongest(t *testing.T) {
	got := dedupe([]Candidate{
		{Task: Task{CWE: "CWE-89", Path: "a.go"}, Severity: "low", Evidence: []string{"a.go:1"}},
		{Task: Task{CWE: "CWE-89", Path: "a.go"}, Severity: "critical", Evidence: []string{"a.go:2", "a.go:3"}},
		{Task: Task{CWE: "CWE-79", Path: "a.go"}, Severity: "medium"},
	})
	if len(got) != 2 {
		t.Fatalf("same path+class should collapse to one, got %d", len(got))
	}
	for _, c := range got {
		if c.CWE == "CWE-89" && c.Severity != "critical" {
			t.Errorf("dedupe should keep the strongest instance, got %s", c.Severity)
		}
	}
}

func TestSweep_GuardsAndCoverage(t *testing.T) {
	if _, err := Sweep(context.Background(), nil, testRepo(), nil, SweepOptions{}); err == nil {
		t.Error("a nil LLM must error")
	}
	// A task naming a file the repo lacks is skipped, not asked about.
	llm := &scriptLLM{fallbk: notVuln}
	res, _ := Sweep(context.Background(), llm, testRepo(), []Task{{CWE: "CWE-89", Path: "ghost.go"}}, SweepOptions{})
	if res.Ran != 0 {
		t.Errorf("an unknown path should not cost a model call, got %+v", res)
	}
	// Coverage is reported so a capped sweep never reads as exhaustive.
	r := Result{Planned: 10, Ran: 4}
	if r.Coverage() != 0.4 {
		t.Errorf("coverage = %v, want 0.4", r.Coverage())
	}
	if (Result{}).Coverage() != 0 {
		t.Error("empty plan coverage should be 0, not NaN")
	}
}

func TestSweep_ModelErrorIsCountedNotFatal(t *testing.T) {
	llm := &scriptLLM{err: errors.New("upstream 503")}
	res, err := Sweep(context.Background(), llm, testRepo(),
		[]Task{{CWE: "CWE-89", Path: "store/users.go"}}, SweepOptions{})
	if err != nil {
		t.Fatalf("a model error should not fail the whole sweep: %v", err)
	}
	if res.Failed != 1 || len(res.Candidates) != 0 {
		t.Errorf("expected a counted failure, got %+v", res)
	}
}

func TestBuildTaskPrompt_NumbersSourceAndDemandsCitation(t *testing.T) {
	f := codelocalize.File{Path: "a.go", Content: "one\ntwo\nthree"}
	p := buildTaskPrompt(Task{CWE: "CWE-89", Path: "a.go", SinkLines: []int{2}}, f, 400)
	for _, want := range []string{"WEAKNESS: CWE-89", "FILE: a.go", "candidate sinks: [2]", "    1 | one", "MUST be a line number shown above"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q:\n%s", want, p)
		}
	}
	// Truncation must be stated, so the model does not reason as if it saw everything.
	long := codelocalize.File{Path: "b.go", Content: strings.Repeat("x\n", 50)}
	if !strings.Contains(buildTaskPrompt(Task{Path: "b.go"}, long, 10), "more lines not shown") {
		t.Error("truncation must be disclosed in the prompt")
	}
}

// Test files are excluded by default: a weakness in a test does not ship, and over a real package
// they dominated the plan (12 tasks → 5 once excluded).
func TestPlan_ExcludesTestFilesByDefault(t *testing.T) {
	repo := codelocalize.Repo{
		{Path: "store/users.go", Content: "db.Query(\"SELECT * FROM t WHERE n='\" + r.URL.Query().Get(\"n\") + \"'\")"},
		{Path: "store/users_test.go", Content: "db.Query(\"SELECT * FROM t WHERE n='\" + r.URL.Query().Get(\"n\") + \"'\")"},
		{Path: "tests/helper.go", Content: "db.Query(\"SELECT * FROM t WHERE n='\" + r.URL.Query().Get(\"n\") + \"'\")"},
	}
	tasks, err := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, repo, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range tasks {
		if isTestPath(k.Path) {
			t.Errorf("test file should not be planned by default: %s", k.Path)
		}
	}
	if len(tasks) == 0 {
		t.Fatal("the shipped file must still be planned")
	}
	// ...and opting in brings them back, for auditing the suite itself.
	withTests, _ := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, repo, PlanOptions{IncludeTests: true})
	if len(withTests) <= len(tasks) {
		t.Errorf("IncludeTests should plan more tasks: %d vs %d", len(withTests), len(tasks))
	}
}

func TestIsTestPath(t *testing.T) {
	for _, p := range []string{
		"a/b_test.go", "web/app.test.js", "web/app.spec.ts", "py/test_thing.py",
		"tests/helper.go", "src/__tests__/x.js", "pkg/testdata/seed.go", "spec/x.rb",
	} {
		if !isTestPath(p) {
			t.Errorf("%q should be recognised as test-only", p)
		}
	}
	for _, p := range []string{"store/users.go", "web/latest.go", "src/contest.js", "protest/main.go"} {
		if isTestPath(p) {
			t.Errorf("%q is shipped code, not a test", p)
		}
	}
}
