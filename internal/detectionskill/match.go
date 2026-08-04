package detectionskill

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// match.go joins a skill to a finding.
//
// Detection Skills are usually authored against SIEM/EDR telemetry fields. Our findings come from OSS
// scanners and posture snapshots, so the join key is rule id / CWE / tool. A skill written purely
// against telemetry simply will not match — reported as "no skill matched", never stretched into a
// loose match. A false match is worse than no match: it would attach someone else's reasoning to an
// unrelated alert and lend it unearned authority.

// Matches reports whether this skill applies to f, and why.
//
// Rule id is matched exactly (case-insensitively) OR as a namespace prefix ending in "::", so a skill
// can target one rule (`nuclei::cve-2024-1234`) or a family (`operate::`). Prefix matching is
// deliberately restricted to the "::" namespace separator — a bare substring match would let the skill
// `s3` claim `s3-bucket-encryption`, `aws-s3-acl` and anything else containing those two letters.
func (s Skill) Matches_(f types.Finding) (bool, string) {
	rule := strings.ToLower(strings.TrimSpace(f.RuleID))
	for _, want := range s.Matches.RuleIDs {
		w := strings.ToLower(strings.TrimSpace(want))
		if w == "" {
			continue
		}
		if rule == w {
			return true, "rule_id " + f.RuleID
		}
		if strings.HasSuffix(w, "::") && strings.HasPrefix(rule, w) {
			return true, "rule namespace " + want
		}
	}
	for _, want := range s.Matches.CWEs {
		for _, have := range f.CWE {
			if strings.EqualFold(normalizeCWEs([]string{have})[0], want) {
				return true, "cwe " + want
			}
		}
	}
	if tool := strings.ToLower(strings.TrimSpace(f.Tool)); tool != "" {
		for _, want := range s.Matches.Tools {
			if tool == want {
				return true, "tool " + f.Tool
			}
		}
	}
	return false, ""
}

// Match is one skill selected for one finding, with the reason it was selected. The reason is carried
// so an analyst (and the evidence pack) can see WHY this skill's reasoning was applied.
type Match struct {
	Skill  Skill
	Reason string
}

// Library is a loaded set of skills.
type Library []Skill

// For returns every skill matching f, in the library's deterministic order. Returning all matches
// rather than "the best one" is intentional: two skills may cover different aspects of the same
// finding, and silently picking one would discard authored reasoning with no audit trail.
func (l Library) For(f types.Finding) []Match {
	var out []Match
	for _, s := range l {
		if ok, why := s.Matches_(f); ok {
			out = append(out, Match{Skill: s, Reason: why})
		}
	}
	return out
}

// Names lists the loaded skill names (for logging and the honest "what is installed" surface).
func (l Library) Names() []string {
	out := make([]string, 0, len(l))
	for _, s := range l {
		out = append(out, s.Name)
	}
	return out
}
