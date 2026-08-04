package detectionskill

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestMatch_ExactRuleAndNamespace(t *testing.T) {
	s := mustSkill(t, "---\nname: identity\nmatches:\n  rule_ids:\n    - operate::\n---\n## Triage\nx\n")
	if ok, why := s.Matches_(types.Finding{RuleID: "operate::stale-account"}); !ok || why == "" {
		t.Fatalf("namespace prefix should match, got ok=%v why=%q", ok, why)
	}
	if ok, _ := s.Matches_(types.Finding{RuleID: "nuclei::cve-2024-1"}); ok {
		t.Fatal("a different namespace must not match")
	}
}

// A bare substring match would let the skill "s3" claim every rule containing those characters.
// Prefix matching is restricted to the "::" namespace separator for exactly this reason.
func TestMatch_DoesNotSubstringMatch(t *testing.T) {
	s := mustSkill(t, "---\nname: s3\nmatches:\n  rule_ids:\n    - s3\n---\n## Triage\nx\n")
	if ok, _ := s.Matches_(types.Finding{RuleID: "aws::s3-bucket-public"}); ok {
		t.Fatal("a loose substring must not match — a false match lends unrelated reasoning unearned authority")
	}
	if ok, _ := s.Matches_(types.Finding{RuleID: "S3"}); !ok {
		t.Fatal("an exact rule id should match case-insensitively")
	}
}

func TestMatch_ByCWEAndTool(t *testing.T) {
	s := mustSkill(t, "---\nname: sqli\nmatches:\n  cwes:\n    - 89\n  tools:\n    - Semgrep\n---\n## Triage\nx\n")
	// "89" in the skill must match "CWE-89" on the finding (normalisation both sides).
	if ok, _ := s.Matches_(types.Finding{CWE: []string{"CWE-89"}}); !ok {
		t.Error("CWE should match regardless of the CWE- prefix")
	}
	if ok, _ := s.Matches_(types.Finding{Tool: "semgrep"}); !ok {
		t.Error("tool should match case-insensitively")
	}
	if ok, _ := s.Matches_(types.Finding{CWE: []string{"CWE-79"}, Tool: "trivy"}); ok {
		t.Error("an unrelated finding must not match")
	}
}

func TestLibrary_ForReturnsAllMatchesDeterministically(t *testing.T) {
	lib := Library{
		mustSkill(t, "---\nname: b-cwe\nmatches:\n  cwes:\n    - 89\n---\n## Triage\nx\n"),
		mustSkill(t, "---\nname: a-rule\nmatches:\n  rule_ids:\n    - semgrep::sqli\n---\n## Triage\nx\n"),
	}
	f := types.Finding{RuleID: "semgrep::sqli", CWE: []string{"CWE-89"}}
	got := lib.For(f)
	if len(got) != 2 {
		t.Fatalf("both skills cover this finding; returning one would discard authored reasoning: %d", len(got))
	}
	// Library order is the caller's; For must preserve it so runs are reproducible.
	if got[0].Skill.Name != "b-cwe" || got[1].Skill.Name != "a-rule" {
		t.Fatalf("match order must follow library order, got %q,%q", got[0].Skill.Name, got[1].Skill.Name)
	}
}

func TestMatch_EmptyMatcherNeverMatches(t *testing.T) {
	s := mustSkill(t, "---\nname: telemetry-only\n---\n## Triage\nx\n")
	if !s.Matches.Empty() {
		t.Fatal("a skill with no join keys should report an empty matcher")
	}
	if ok, _ := s.Matches_(types.Finding{RuleID: "anything", Tool: "any", CWE: []string{"CWE-1"}}); ok {
		t.Fatal("a skill written purely against SIEM telemetry must simply not match — never stretched into one")
	}
}

func TestFrontmatter_ParsesScalarsListsAndMaps(t *testing.T) {
	s := mustSkill(t, `---
name: "quoted name"
description: 'single quoted'
version: 2.1.0
matches:
  rule_ids:
    - a::b
    - c::d
  cwes:
    - 89
---
## Triage
t
## Investigation
i
## Tuning
u
`)
	if s.Name != "quoted name" || s.Description != "single quoted" || s.Version != "2.1.0" {
		t.Fatalf("scalars wrong: %+v", s)
	}
	if len(s.Matches.RuleIDs) != 2 || s.Matches.RuleIDs[1] != "c::d" {
		t.Fatalf("list wrong: %v", s.Matches.RuleIDs)
	}
	if len(s.Matches.CWEs) != 1 || s.Matches.CWEs[0] != "CWE-89" {
		t.Fatalf("cwe normalisation wrong: %v", s.Matches.CWEs)
	}
	if s.Triage != "t" || s.Investigation != "i" || s.Tuning != "u" {
		t.Fatalf("sections wrong: %q %q %q", s.Triage, s.Investigation, s.Tuning)
	}
}

func TestParse_RequiresFrontmatterAndAPhase(t *testing.T) {
	if _, err := parseSkill([]byte("## Triage\nno frontmatter\n"), "s"); err == nil {
		t.Error("frontmatter is required — provenance is non-negotiable")
	}
	if _, err := parseSkill([]byte("---\nname: x\n---\n## Tuning\nonly tuning\n"), "s"); err == nil {
		t.Error("a skill with neither triage nor investigation has nothing to run")
	}
	if _, err := parseSkill([]byte("---\nname:\n---\n## Triage\nx\n"), "s"); err == nil {
		t.Error("a nameless skill cannot be attributed and must be refused")
	}
}

func TestDigest_ChangesWithContent(t *testing.T) {
	a := mustSkill(t, "---\nname: t\n---\n## Triage\nversion one\n")
	b := mustSkill(t, "---\nname: t\n---\n## Triage\nversion two\n")
	if a.Digest == b.Digest {
		t.Fatal("digest must change with content — it is what an evidence pack pins")
	}
	if len(a.Digest) != 64 {
		t.Fatalf("expected a sha256 hex digest, got %q", a.Digest)
	}
}
