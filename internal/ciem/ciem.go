// Package ciem is the Cloud Infrastructure Entitlement Management core — the "you were granted 500
// permissions and used 12" rightsizing a senior cloud-security engineer does by hand, and a named
// Wiz/Orca differentiator tsengine lacked. Given a principal's GRANTED action set (from its identity
// policies) and the actions it ACTUALLY USED in an observation window (CloudTrail / IAM last-accessed /
// Access Analyzer), Rightsize reports the unused (over-privileged) actions + a least-privilege
// recommendation.
//
// Grounding (§10, the honest gate): a finding is produced ONLY for a principal we have real usage data
// for (Usage.Observed). Absence of usage data is NOT "unused" — it means we can't see, so we don't
// claim. The granted side is real (extracted from the snapshot's policies); the usage side is the
// gated live-ingest half (same discipline as every ADR-0010 core). Pure + deterministic + tested.
package ciem

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// Grant is a principal's effectively-granted action set (canonical "service:Action" tokens, or a
// wildcard like "s3:*" / "*"). Privileged marks a principal the graph already flagged high-privilege.
type Grant struct {
	Principal  string
	Actions    []string
	Privileged bool
}

// Usage is what a principal actually invoked in the window. Observed is the honest gate: false means we
// had no usage data (so we make no over-privilege claim); true with empty Actions means "observed, used
// nothing" — the strongest dormant-identity signal.
type Usage struct {
	Actions    []string
	WindowDays int
	Observed   bool
}

// Finding is an over-privileged principal. Grounded: only emitted when usage was Observed.
type Finding struct {
	Principal      string   `json:"principal"`
	UnusedActions  []string `json:"unused_actions,omitempty"`  // granted, wildcard-or-literal, never used in the window
	OverbroadHints []string `json:"overbroad_hints,omitempty"` // "s3:* → used only [s3:GetObject]" narrowing hints
	WindowDays     int      `json:"window_days"`
	GrantedCount   int      `json:"granted_count"`
	UsedCount      int      `json:"used_count"`
	Severity       string   `json:"severity"` // high | medium | low
	Recommendation string   `json:"recommendation"`
}

// dangerousPrefixes are the grants whose standing-but-unused presence is high severity (a dormant path
// to escalation / data theft). Matched case-insensitively as a prefix of the granted action.
var dangerousPrefixes = []string{
	"*", "iam:", "sts:assumerole", "sts:*", "s3:*", "kms:decrypt", "kms:*",
	"secretsmanager:getsecretvalue", "secretsmanager:*", "ec2:*", "lambda:*", "organizations:",
}

// Rightsize diffs each principal's granted vs used actions and returns the over-privileged findings,
// most-severe first. Only principals with Observed usage are assessed (the honest gate).
func Rightsize(grants []Grant, usage map[string]Usage) []Finding {
	var out []Finding
	for _, g := range grants {
		u, ok := usage[g.Principal]
		if !ok || !u.Observed {
			continue // no usage data → no claim (§10)
		}
		usedSet := lowerSet(u.Actions)
		var unused, overbroad []string
		for _, a := range g.Actions {
			la := strings.ToLower(strings.TrimSpace(a))
			if la == "" {
				continue
			}
			if isWildcard(la) {
				matched := matchWildcard(la, u.Actions)
				if len(matched) == 0 {
					unused = append(unused, a) // a wildcard grant that matched zero usage → fully unused
				} else {
					// the wildcard was used, but is broader than the concrete actions observed — recommend
					// narrowing it to exactly what was used.
					sort.Strings(matched)
					overbroad = append(overbroad, fmt.Sprintf("%s → used only [%s]", a, strings.Join(matched, ", ")))
				}
			} else if !usedSet[la] {
				unused = append(unused, a)
			}
		}
		if len(unused) == 0 && len(overbroad) == 0 {
			continue // fully right-sized → nothing to report
		}
		sort.Strings(unused)
		f := Finding{
			Principal:      g.Principal,
			UnusedActions:  unused,
			OverbroadHints: overbroad,
			WindowDays:     u.WindowDays,
			GrantedCount:   len(g.Actions),
			UsedCount:      len(u.Actions),
			Severity:       severity(g, unused),
			Recommendation: recommend(g, unused, overbroad, u.WindowDays, len(g.Actions)-len(unused)),
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) > sevRank(out[j].Severity) })
	return out
}

// severity: a dormant PRIVILEGED grant (or an unused dangerous action) is high — standing privilege the
// principal has never exercised is the prime CIEM risk; otherwise any unused grant is medium.
func severity(g Grant, unused []string) string {
	for _, a := range unused {
		if g.Privileged || isDangerous(a) {
			return "high"
		}
	}
	if len(unused) > 0 {
		return "medium"
	}
	return "low" // only over-broad wildcards (used, but too wide)
}

func recommend(g Grant, unused, overbroad []string, window, usedGranted int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s exercised %d of %d granted actions", g.Principal, usedGranted, len(g.Actions))
	if window > 0 {
		fmt.Fprintf(&b, " in the last %dd", window)
	}
	b.WriteString(". Apply least privilege: ")
	if len(unused) > 0 {
		fmt.Fprintf(&b, "remove %d unused action(s) (%s)", len(unused), strings.Join(cap8(unused), ", "))
	}
	if len(overbroad) > 0 {
		if len(unused) > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "narrow %d over-broad wildcard grant(s) to the used subset", len(overbroad))
	}
	b.WriteString(".")
	return b.String()
}

// GrantFromDocuments extracts a principal's granted action set from its identity policy Documents.
// Allow statements contribute their Action tokens; an Allow that uses NotAction (allow-all-except) is
// treated conservatively as a "*" wildcard grant (maximally over-broad). Deny statements are ignored
// (Rightsize is about what's granted-but-unused, and a Deny grants nothing).
func GrantFromDocuments(principal string, privileged bool, docs []*cloudiam.Document) Grant {
	seen := map[string]bool{}
	var actions []string
	add := func(a string) {
		a = strings.TrimSpace(a)
		if a != "" && !seen[strings.ToLower(a)] {
			seen[strings.ToLower(a)] = true
			actions = append(actions, a)
		}
	}
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, st := range d.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			if len(st.Action) == 0 && len(st.NotAction) > 0 {
				add("*") // NotAction Allow = allow everything except listed → treat as maximally broad
				continue
			}
			for _, a := range st.Action {
				add(a)
			}
		}
	}
	return Grant{Principal: principal, Actions: actions, Privileged: privileged}
}

// --- helpers ---

func isWildcard(a string) bool {
	return a == "*" || strings.HasSuffix(a, ":*") || strings.HasSuffix(a, "*")
}

// matchWildcard returns the used actions covered by wildcard grant w (e.g. "s3:*" covers "s3:GetObject").
func matchWildcard(w string, used []string) []string {
	prefix := strings.TrimSuffix(strings.ToLower(w), "*")
	var out []string
	for _, u := range used {
		lu := strings.ToLower(strings.TrimSpace(u))
		if lu == "" {
			continue
		}
		if w == "*" || strings.HasPrefix(lu, prefix) {
			out = append(out, u)
		}
	}
	return out
}

func isDangerous(a string) bool {
	la := strings.ToLower(strings.TrimSpace(a))
	for _, p := range dangerousPrefixes {
		if la == p || strings.HasPrefix(la, p) {
			return true
		}
	}
	return false
}

func lowerSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[strings.ToLower(strings.TrimSpace(x))] = true
	}
	return m
}

func cap8(xs []string) []string {
	if len(xs) <= 8 {
		return xs
	}
	return append(append([]string{}, xs[:8]...), "…")
}

func sevRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
