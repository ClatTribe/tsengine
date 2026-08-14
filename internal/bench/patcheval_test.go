package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PatchEval ships the answer inside every instance — fix_func and patch_url. Their own prompts
// withhold them. An adapter that passed them through would score beautifully and mean nothing, and it
// would fail SILENTLY: a leaked benchmark is indistinguishable from a capable agent.

func instance() PatchEvalInstance {
	return PatchEvalInstance{
		CVEID:          "CVE-2021-23376",
		CVEDescription: "Prototype pollution in the merge helper allows an attacker to modify Object.prototype.",
		CWEInfo:        "CWE-1321",
		Repo:           "example/widgets",
		Language:       "JavaScript",
		ImageURL:       "patcheval/cve-2021-23376:latest",
		PatchURL:       "https://github.com/example/widgets/commit/deadbeefdeadbeefdeadbeef",
		FixFunc:        "function merge(target, source) { if (key === '__proto__') return; /* the actual fix */ }",
		VulFunc:        "function merge(target, source) { for (const key in source) target[key] = source[key]; }",
	}
}

// ── THE GUARD ────────────────────────────────────────────────────────────────────────────────────

// The agent may see the description, CWE, repo and language. It may not see the fix.
func TestPromptFields_CannotCarryTheAnswer(t *testing.T) {
	p := PromptFields(instance())
	blob := p.CVEID + p.Description + p.CWE + p.Repo + p.Language

	for name, answer := range map[string]string{
		"fix_func":  instance().FixFunc,
		"patch_url": instance().PatchURL,
	} {
		if strings.Contains(blob, answer) {
			t.Errorf("%s reached the prompt fields — the benchmark would be measuring nothing", name)
		}
	}
	// And it must still carry enough to be a real task.
	if p.Description == "" || p.CWE == "" || p.Repo == "" {
		t.Errorf("the prompt fields dropped something the agent legitimately needs: %+v", p)
	}
}

// The second lock: prompts are assembled from several sources, so the rendered text is checked for the
// answer mechanically rather than reasoned about.
func TestLeakedInto_CatchesTheAnswerInRenderedText(t *testing.T) {
	in := instance()

	clean := "Fix the prototype-pollution vulnerability in example/widgets (CWE-1321)."
	if got := LeakedInto(clean, in); len(got) != 0 {
		t.Errorf("a clean prompt was reported as leaking: %v", got)
	}

	withFix := clean + "\n\nHere is the fix: " + in.FixFunc
	if got := LeakedInto(withFix, in); len(got) == 0 {
		t.Error("a prompt containing fix_func was NOT detected — this is the failure that looks like success")
	}

	withURL := clean + "\nSee " + in.PatchURL
	if got := LeakedInto(withURL, in); len(got) == 0 {
		t.Error("a prompt containing patch_url was not detected")
	}
}

// The guard must not cry wolf on short fragments, or it becomes noise and gets ignored.
func TestLeakedInto_IgnoresFragmentsTooShortToBeDistinctive(t *testing.T) {
	in := PatchEvalInstance{CVEID: "CVE-1", FixFunc: "get", PatchURL: "x"}
	if got := LeakedInto("the agent should get the repo", in); len(got) != 0 {
		t.Errorf("a 3-character fix_func matched ordinary prose: %v", got)
	}
}

// ── LOADING ──────────────────────────────────────────────────────────────────────────────────────

func TestLoadPatchEval_ParsesTheirFieldNames(t *testing.T) {
	// Note "programing_language" — their spelling. Getting this wrong silently yields empty languages.
	raw := `[{"cve_id":"CVE-2020-1","cve_description":"d","cwe_info":"CWE-79",
	          "repo":"o/r","programing_language":"Python","image_url":"img",
	          "patch_url":"u","fix_func":"f","vul_func":"v"}]`
	p := filepath.Join(t.TempDir(), "patcheval_verified.json")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	xs, err := LoadPatchEval(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(xs) != 1 {
		t.Fatalf("got %d instances, want 1", len(xs))
	}
	if xs[0].Language != "Python" {
		t.Errorf("language = %q — their field is 'programing_language' (one m)", xs[0].Language)
	}
	if xs[0].FixFunc != "f" {
		t.Error("the answer fields must still be PARSED, so a run can assert they never reached the model")
	}
}

func TestLoadPatchEval_RefusesAnInstanceWithNoCVE(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(p, []byte(`[{"cve_description":"d"}]`), 0o644)
	if _, err := LoadPatchEval(p); err == nil {
		t.Error("an instance with no cve_id was accepted — its submission could never be matched back")
	}
}

// ── SUBMISSION ───────────────────────────────────────────────────────────────────────────────────

func TestWriteSubmission_MatchesTheirExpectedShape(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSubmission(dir, PatchEvalSubmission{CVE: "CVE-2021-23376", FixPatch: "diff --git a/x b/x\n"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "CVE-2021-23376.json"))
	if err != nil {
		t.Fatalf("submission not written where their evaluator looks: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	// Their evaluator reads exactly these two keys.
	if got["cve"] != "CVE-2021-23376" || !strings.HasPrefix(got["fix_patch"], "diff --git") {
		t.Errorf("submission shape is wrong: %v", got)
	}
}

// A case we failed on gets an EMPTY patch, not a missing file. Silently omitting failures is how a
// score improves without the agent improving.
func TestWriteSubmission_WritesEmptyPatchRatherThanSkipping(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSubmission(dir, PatchEvalSubmission{CVE: "CVE-2020-9999", FixPatch: ""}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "CVE-2020-9999.json")); err != nil {
		t.Error("a failed case produced no file — the run would look better than it was")
	}
}

func TestWriteSubmission_RefusesAnUnidentifiedSubmission(t *testing.T) {
	if err := WriteSubmission(t.TempDir(), PatchEvalSubmission{FixPatch: "diff"}); err == nil {
		t.Error("a submission with no CVE id was written; nothing could match it back to a task")
	}
}

func TestSafeCVEName_SurvivesDataWeDidNotAuthor(t *testing.T) {
	if got := safeCVEName("../../etc/passwd"); strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Errorf("path separators survived into a filename: %q", got)
	}
	if got := safeCVEName(""); got != "unknown" {
		t.Errorf("empty id = %q, want unknown", got)
	}
}
