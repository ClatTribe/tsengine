package detectionskill

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func shippedLibrary(t *testing.T) Library {
	t.Helper()
	lib, errs := LoadDir(filepath.Join("..", "..", "skills"))
	if len(errs) > 0 {
		t.Fatalf("every shipped skill must load cleanly: %v", errs)
	}
	if len(lib) == 0 {
		t.Fatal("no shipped skills found")
	}
	return lib
}

// The Convert move (ADR 0017): the per-rule reasoning that was trapped in Go should now be portable.
// This asserts the shipped library actually covers every identity rule remediate/identity.go handles,
// read from the SOURCE so adding a runbook without a skill fails here rather than drifting silently.
func TestShippedLibrary_CoversEveryIdentityRunbook(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "remediate", "identity.go"))
	if err != nil {
		t.Skipf("remediate/identity.go not readable (%v) — skipping coverage cross-check", err)
	}
	re := regexp.MustCompile(`case "(operate::[a-z-]+)"`)
	var rules []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		rules = append(rules, m[1])
	}
	if len(rules) < 5 {
		t.Fatalf("expected the identity runbook set, found %d rules", len(rules))
	}

	lib := shippedLibrary(t)
	for _, rule := range rules {
		f := types.Finding{ID: "f-1", RuleID: rule, Tool: "operate"}
		if got := lib.For(f); len(got) == 0 {
			t.Errorf("rule %q has a Go runbook but no Detection Skill covers it — the Convert move is incomplete", rule)
		}
	}
}

// A skill's authored guidance is worthless if the phases are empty. Every shipped skill must actually
// say something in the phases it claims.
func TestShippedLibrary_SkillsAreSubstantive(t *testing.T) {
	for _, s := range shippedLibrary(t) {
		if s.Description == "" {
			t.Errorf("skill %q has no description", s.Name)
		}
		if s.Version == "" {
			t.Errorf("skill %q has no version — a verdict pins the skill, so it needs one", s.Name)
		}
		if s.Matches.Empty() {
			t.Errorf("skill %q matches nothing and can never fire", s.Name)
		}
		if len(s.Triage) < 100 || len(s.Investigation) < 100 {
			t.Errorf("skill %q has a stub phase (triage=%d, investigation=%d chars) — a skill exists to carry real reasoning",
				s.Name, len(s.Triage), len(s.Investigation))
		}
		// The valuable half of triage is knowing when NOT to escalate.
		if !strings.Contains(strings.ToLower(s.Triage), "benign") &&
			!strings.Contains(strings.ToLower(s.Triage), "dismiss") {
			t.Errorf("skill %q never states when to dismiss — that is the half analysts most need", s.Name)
		}
	}
}

// Our own skills must obey the same trust boundary we impose on third-party ones. If a shipped skill
// ever claimed capability, the loader would refuse it — this proves we are not exempting ourselves.
func TestShippedLibrary_ClaimsNoCapability(t *testing.T) {
	root := filepath.Join("..", "..", "skills")
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != SkillFile {
			return nil //nolint:nilerr // unreadable entries are skipped
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		fm, _, perr := splitFrontmatter(raw)
		if perr != nil {
			t.Errorf("%s: %v", p, perr)
			return nil
		}
		if cerr := rejectCapabilityKeys(fm); cerr != nil {
			t.Errorf("%s: our own skill claims capability: %v", p, cerr)
		}
		return nil
	})
}

// Skill names must be unique — a verdict is attributed by name, so two skills sharing one would make
// provenance ambiguous in an evidence pack.
func TestShippedLibrary_NamesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, s := range shippedLibrary(t) {
		if prev, dup := seen[s.Name]; dup {
			t.Errorf("duplicate skill name %q (%s and %s) — provenance would be ambiguous", s.Name, prev, s.Source)
		}
		seen[s.Name] = s.Source
	}
}
