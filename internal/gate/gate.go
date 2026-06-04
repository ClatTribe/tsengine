// Package gate is the CI/CD security gate — the Shift-Left entry point. It takes
// the engine's findings (an L1 scan, a web-exploit evidence bundle, or SCA
// reachability results), evaluates them against a declarative policy, and returns
// pass/fail so a pipeline can block a merge. Two ideas make it useful rather than
// noisy: (1) it gates on what the engine *proved* — a verified exploit or a
// reachable dependency CVE outweighs a raw severity label; (2) it supports a
// baseline so you fail on NEW risk, not pre-existing debt, plus waivers for
// accepted findings.
package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Finding is the gate-normalized view of one issue.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`      // scan | web | llm | sca
	Verified    bool   `json:"verified"`    // proved exploitable / re-confirmed
	Reachable   bool   `json:"reachable"`   // SCA: the vulnerable symbol is reachable
	Fingerprint string `json:"fingerprint"` // stable identity for baseline/waivers
}

// Waiver suppresses a finding by fingerprint, with a reason and optional expiry
// (RFC3339 date). An expired waiver no longer suppresses.
type Waiver struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
	Expires     string `json:"expires,omitempty"`
}

// Policy is the declarative gate config.
type Policy struct {
	FailOnSeverity     string   `json:"fail_on_severity,omitempty"` // fail if any finding ≥ this (critical|high|medium|low); "" disables
	FailOnVerified     bool     `json:"fail_on_verified"`           // any verified/proven finding fails
	FailOnReachableSCA bool     `json:"fail_on_reachable_sca"`      // any reachable dependency CVE fails
	MaxNewFindings     int      `json:"max_new_findings"`           // fail if new (vs baseline) findings exceed this; <0 disables
	NewOnly            bool     `json:"new_only"`                   // only gate on findings absent from the baseline
	Waivers            []Waiver `json:"waivers,omitempty"`
}

// DefaultPolicy: block on a high-or-worse finding, any proven exploit, or any
// reachable dependency CVE. Pre-existing debt is not gated unless you opt in.
func DefaultPolicy() Policy {
	return Policy{FailOnSeverity: "high", FailOnVerified: true, FailOnReachableSCA: true, MaxNewFindings: -1}
}

// Violation is one reason the gate failed.
type Violation struct {
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	Reason      string `json:"reason"`
}

// Result is the gate outcome.
type Result struct {
	Passed     bool           `json:"passed"`
	Total      int            `json:"total"`
	Gated      int            `json:"gated"` // evaluated after new-only + waivers
	New        int            `json:"new"`   // gated findings absent from baseline
	Waived     int            `json:"waived"`
	Existing   int            `json:"existing"` // skipped because present in baseline (new-only)
	Counts     map[string]int `json:"severity_counts"`
	Violations []Violation    `json:"violations,omitempty"`
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func rank(s string) int {
	if r, ok := sevRank[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}

// Fingerprint is the stable identity used for baseline + waiver matching.
func Fingerprint(f Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	key := strings.ToLower(f.Source + "|" + f.Severity + "|" + f.Title)
	sum := sha256.Sum256([]byte(key))
	return "g-" + hex.EncodeToString(sum[:])[:12]
}

// Evaluate applies the policy. baseline is the set of fingerprints accepted in a
// prior run (nil = none); now is the clock (waiver expiry).
func Evaluate(findings []Finding, p Policy, baseline map[string]bool, now time.Time) Result {
	waived := activeWaivers(p.Waivers, now)
	r := Result{Total: len(findings), Counts: map[string]int{}, Passed: true}

	for i := range findings {
		f := &findings[i]
		f.Fingerprint = Fingerprint(*f)
		r.Counts[strings.ToLower(f.Severity)]++

		if waived[f.Fingerprint] {
			r.Waived++
			continue
		}
		isNew := baseline == nil || !baseline[f.Fingerprint]
		if p.NewOnly && !isNew {
			r.Existing++
			continue
		}
		r.Gated++
		if isNew {
			r.New++
		}

		if reason := violates(*f, p); reason != "" {
			r.Violations = append(r.Violations, Violation{
				Fingerprint: f.Fingerprint, Title: f.Title, Severity: f.Severity, Source: f.Source, Reason: reason,
			})
		}
	}

	if p.MaxNewFindings >= 0 && r.New > p.MaxNewFindings {
		r.Violations = append(r.Violations, Violation{
			Reason: fmt.Sprintf("too many new findings: %d new > %d allowed", r.New, p.MaxNewFindings),
		})
	}
	sort.SliceStable(r.Violations, func(i, j int) bool {
		return rank(r.Violations[i].Severity) < rank(r.Violations[j].Severity)
	})
	r.Passed = len(r.Violations) == 0
	return r
}

// violates returns the strongest reason a finding fails the policy, or "".
//
// SCA findings are gated PURELY on reachability — an unreachable dependency CVE,
// however "critical" its label, does not block. That is the entire point of
// reachability triage; gating SCA on raw severity would put the noise right back.
// Non-SCA findings (scan/web/llm) gate on proof (verified) then severity.
func violates(f Finding, p Policy) string {
	if f.Source == "sca" {
		if p.FailOnReachableSCA && f.Reachable {
			return "reachable dependency vulnerability (the vulnerable function is on a call path)"
		}
		return "" // unreachable / unused dependency CVE → not gated
	}
	if p.FailOnVerified && f.Verified {
		return "verified/proven exploitable"
	}
	if p.FailOnSeverity != "" && rank(f.Severity) <= rank(p.FailOnSeverity) {
		return "severity " + strings.ToLower(f.Severity) + " ≥ threshold " + strings.ToLower(p.FailOnSeverity)
	}
	return ""
}

func activeWaivers(ws []Waiver, now time.Time) map[string]bool {
	m := map[string]bool{}
	for _, w := range ws {
		if w.Expires != "" {
			if exp, err := time.Parse(time.RFC3339, w.Expires); err == nil && now.After(exp) {
				continue // expired → no longer suppresses
			}
		}
		m[w.Fingerprint] = true
	}
	return m
}

// Fingerprints returns the fingerprints of all findings (to snapshot a baseline).
func Fingerprints(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, Fingerprint(f))
	}
	sort.Strings(out)
	return out
}
