package crossdetect

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// exclude.go is the "custom rules" noise filter (Aikido parity: exclude specific
// paths, packages, conditions). It drops findings matching a tenant's ExclusionRule
// globs BEFORE they are unified into issues — so excluded noise never appears.
//
// Grounded: a rule matches against real finding attributes (rule id, package
// coordinate, endpoint/path, CVE); the match is a plain glob, nothing inferred.

// ApplyExclusions returns the findings NOT matched by any exclusion rule (order
// preserved). With no rules it returns the input unchanged.
func ApplyExclusions(findings []types.Finding, rules []platform.ExclusionRule) []types.Finding {
	if len(rules) == 0 {
		return findings
	}
	out := findings[:0:0] // new backing array; never alias the caller's slice
	for _, f := range findings {
		if _, hit := ExcludedBy(f, rules); !hit {
			out = append(out, f)
		}
	}
	return out
}

// ExcludedBy reports the first rule that excludes a finding (and whether any did).
func ExcludedBy(f types.Finding, rules []platform.ExclusionRule) (platform.ExclusionRule, bool) {
	for _, r := range rules {
		if strings.TrimSpace(r.Pattern) == "" {
			continue
		}
		for _, v := range exclFieldValues(f, r.Field) {
			if v != "" && globMatch(r.Pattern, v) {
				return r, true
			}
		}
	}
	return platform.ExclusionRule{}, false
}

// exclFieldValues extracts the matchable value(s) of a finding for a rule field.
func exclFieldValues(f types.Finding, field string) []string {
	switch field {
	case platform.ExclByRule:
		return []string{f.RuleID}
	case platform.ExclByPackage:
		return []string{f.ToolArgs["pkg"]}
	case platform.ExclByPath:
		return []string{f.Endpoint}
	case platform.ExclByCVE:
		if m := cveRe.FindString(f.RuleID + " " + f.Title); m != "" {
			return []string{m}
		}
		return nil
	default: // ExclByAny (and unknown → widest match, never narrower than intended)
		return []string{f.RuleID, f.Endpoint, f.ToolArgs["pkg"], f.Title}
	}
}

// globMatch reports whether pattern (with '*' wildcards) matches s, case-insensitively.
// '*' matches any run of characters (including '/' and ':' — intuitive for rule ids,
// PURLs, and paths). No wildcard → exact (case-insensitive) match.
func globMatch(pattern, s string) bool {
	pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
