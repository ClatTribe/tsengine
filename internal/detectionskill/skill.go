// Package detectionskill loads and runs Detection Skills (https://detectionskills.io) — the open
// format, stewarded by Vega, that packages a detection rule together with the investigation reasoning
// a detection engineer would apply. A skill is a folder with a SKILL.md: YAML frontmatter plus a
// markdown body with Triage / Investigation / Tuning sections. It is the Agent Skills format, so
// anything that runs Agent Skills runs a Detection Skill.
//
// WHY WE CONSUME RATHER THAN COMPETE (ADR 0017): formats commoditize. The scarce asset is the
// substrate that can GROUND a skill (real tools, sandbox, pinned corpus, evidence pack) and STAND
// BEHIND its verdict (a named human, a signed ledger). Skills are the input; evidence is the output.
//
// THE TRUST BOUNDARY IS THE POINT OF THIS PACKAGE. A community SKILL.md is untrusted instructions that
// an agent will follow — prompt injection as a supply chain. So:
//
//   - A skill is DATA, never capability. It cannot grant a tool, widen scope/budget/egress, or change
//     a gate tier. Capability-claiming frontmatter is refused at load (see trust.go).
//   - A skill PROPOSES; the framework DISPOSES. A verdict is validated against a closed enum and every
//     cited finding id must really exist in the incident under triage (verdict.go).
//   - Provenance is pinned. Every skill carries a SHA-256 content digest so an evidence pack can state
//     exactly which skill version produced a verdict.
//
// This is the same "agent proposes, framework disposes" model the engine already runs on (CLAUDE.md
// §10), not a second safety story.
package detectionskill

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SkillFile is the required filename inside a skill folder (the Agent Skills convention).
const SkillFile = "SKILL.md"

// Matcher decides which findings a skill applies to. Detection Skills are usually written against
// SIEM/EDR telemetry; our findings come from OSS scanners and posture snapshots, so rule id / CWE /
// tool is the join key. A skill matching on none of these simply never matches — reported honestly as
// "no skill matched", never stretched into a false match.
type Matcher struct {
	RuleIDs []string `json:"rule_ids,omitempty"`
	CWEs    []string `json:"cwes,omitempty"`
	Tools   []string `json:"tools,omitempty"`
}

// Empty reports whether this matcher can never match anything.
func (m Matcher) Empty() bool { return len(m.RuleIDs) == 0 && len(m.CWEs) == 0 && len(m.Tools) == 0 }

// Skill is one loaded Detection Skill.
//
// Note what is ABSENT by design: there is no field by which a skill can request a tool, a scope, a
// budget, an egress destination, or a gate tier. The type itself is the first line of the trust
// boundary — a malicious skill has nowhere to put such a request.
type Skill struct {
	Name        string
	Description string
	Version     string
	Matches     Matcher

	// The three phases, as authored markdown. These are UNTRUSTED TEXT: they are only ever rendered
	// into a prompt inside explicit untrusted-content delimiters (RenderContext), never executed and
	// never interpreted as configuration.
	Triage        string
	Investigation string
	Tuning        string

	// Provenance — what an evidence pack pins.
	Source string // path the skill was loaded from
	Digest string // sha256 of the raw SKILL.md bytes
}

// Load parses a single SKILL.md file. It validates the trust boundary before returning, so a caller
// can never hold a Skill that was refused.
func Load(path string) (Skill, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Skill{}, fmt.Errorf("read skill %q: %w", path, err)
	}
	return parseSkill(raw, path)
}

// parseSkill turns raw SKILL.md bytes into a validated Skill.
func parseSkill(raw []byte, source string) (Skill, error) {
	fm, body, err := splitFrontmatter(raw)
	if err != nil {
		return Skill{}, fmt.Errorf("%s: %w", source, err)
	}
	if err := rejectCapabilityKeys(fm); err != nil {
		return Skill{}, fmt.Errorf("%s: %w", source, err)
	}

	sum := sha256.Sum256(raw)
	s := Skill{
		Name:        fm.str("name"),
		Description: fm.str("description"),
		Version:     fm.str("version"),
		Matches: Matcher{
			RuleIDs: fm.list("matches", "rule_ids"),
			CWEs:    normalizeCWEs(fm.list("matches", "cwes")),
			Tools:   lowerAll(fm.list("matches", "tools")),
		},
		Source: source,
		Digest: hex.EncodeToString(sum[:]),
	}
	s.Triage = section(body, "triage")
	s.Investigation = section(body, "investigation")
	s.Tuning = section(body, "tuning")

	if s.Name == "" {
		return Skill{}, fmt.Errorf("%s: SKILL.md needs a `name` in its frontmatter", source)
	}
	if s.Triage == "" && s.Investigation == "" {
		return Skill{}, fmt.Errorf("%s: skill %q has neither a Triage nor an Investigation section — nothing to run", source, s.Name)
	}
	return s, nil
}

// LoadDir walks root and loads every skill folder beneath it (any directory containing a SKILL.md).
// A skill that fails to parse or fails the trust check is SKIPPED with its error collected, never
// silently dropped and never allowed to abort the whole library: one bad third-party skill must not
// disable every good one.
func LoadDir(root string) ([]Skill, []error) {
	var skills []Skill
	var errs []error

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != SkillFile {
			return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
		}
		s, lerr := Load(p)
		if lerr != nil {
			errs = append(errs, lerr)
			return nil
		}
		skills = append(skills, s)
		return nil
	})

	// Deterministic order: the same library must produce the same match order every run (§10
	// reproducibility — a verdict cites a skill, so ordering must not drift between runs).
	sort.Slice(skills, func(i, j int) bool { return skills[i].Name < skills[j].Name })
	return skills, errs
}

// section extracts a markdown `## <heading>` block (case-insensitive), up to the next `## ` heading.
func section(body, heading string) string {
	lines := strings.Split(body, "\n")
	var out []string
	in := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") {
			h := strings.ToLower(strings.TrimSpace(strings.TrimLeft(t, "# ")))
			if h == heading || strings.HasPrefix(h, heading+" ") {
				in = true
				continue
			}
			if in {
				break // next heading ends the section
			}
		}
		if in {
			out = append(out, ln)
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

// normalizeCWEs upper-cases and ensures the CWE- prefix so "89", "cwe-89" and "CWE-89" all match.
func normalizeCWEs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		out = append(out, "CWE-"+strings.TrimPrefix(s, "CWE-"))
	}
	return out
}
