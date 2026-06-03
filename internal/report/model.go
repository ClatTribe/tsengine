// Package report turns the engine's machine outputs (the L1 dashboard
// vulnerabilities.json, the web agent's signed evidence bundle, an LLM red-team
// report) into a branded, human-facing security report — the actual sellable VAPT
// deliverable (roadmap §4 / §7-#1). One normalized model, several adapters in, two
// renderers out (Markdown + self-contained HTML).
package report

import (
	"sort"
	"strings"
	"time"
)

// Report is the normalized, render-ready model.
type Report struct {
	Title       string            `json:"title"`
	Kind        string            `json:"kind"` // e.g. "Web Application Penetration Test"
	Target      string            `json:"target"`
	Org         string            `json:"org,omitempty"`
	GeneratedAt time.Time         `json:"generated_at"`
	Engine      string            `json:"engine,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Findings    []Finding         `json:"findings"`
	Methodology []string          `json:"methodology,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Signed      bool              `json:"signed,omitempty"`
	Signer      string            `json:"signer,omitempty"`
}

// Finding is one render-ready issue.
type Finding struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Severity    string              `json:"severity"`
	Status      string              `json:"status,omitempty"` // verified | corroborated | pattern_match
	Endpoint    string              `json:"endpoint,omitempty"`
	Tool        string              `json:"tool,omitempty"`
	Description string              `json:"description,omitempty"`
	Evidence    []string            `json:"evidence,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
	CWE         []string            `json:"cwe,omitempty"`
	ThreatIntel string              `json:"threat_intel,omitempty"`
	Compliance  map[string][]string `json:"compliance,omitempty"`
}

// severityRank orders severities high→low for sorting + risk rating.
var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func rank(sev string) int {
	if r, ok := severityRank[strings.ToLower(sev)]; ok {
		return r
	}
	return 5
}

// Counts returns the finding count per severity.
func (r *Report) Counts() map[string]int {
	c := map[string]int{}
	for _, f := range r.Findings {
		c[strings.ToLower(f.Severity)]++
	}
	return c
}

// RiskRating is the headline rating: the highest severity present (or "None").
func (r *Report) RiskRating() string {
	best := 6
	for _, f := range r.Findings {
		if x := rank(f.Severity); x < best {
			best = x
		}
	}
	for sev, x := range severityRank {
		if x == best {
			return strings.Title(sev) //nolint:staticcheck // ASCII severity words
		}
	}
	return "None"
}

// Verified reports how many findings were independently confirmed.
func (r *Report) Verified() int {
	n := 0
	for _, f := range r.Findings {
		if f.Status == "verified" {
			n++
		}
	}
	return n
}

// sortFindings orders by severity (critical first) then title — deterministic
// output so reports diff cleanly.
func (r *Report) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		ri, rj := rank(r.Findings[i].Severity), rank(r.Findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return r.Findings[i].Title < r.Findings[j].Title
	})
}

// autoSummary writes a factual executive summary from the counts when the adapter
// didn't supply one.
func (r *Report) autoSummary() string {
	if r.Summary != "" {
		return r.Summary
	}
	c := r.Counts()
	total := len(r.Findings)
	if total == 0 {
		return "This assessment identified no exploitable findings against " + r.Target + " within the tested scope."
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c[sev] > 0 {
			parts = append(parts, plural(c[sev], sev))
		}
	}
	b := &strings.Builder{}
	b.WriteString("This assessment of ")
	b.WriteString(r.Target)
	b.WriteString(" identified ")
	b.WriteString(plural(total, "finding"))
	if len(parts) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString(")")
	}
	b.WriteString(". Overall risk is rated ")
	b.WriteString(r.RiskRating())
	b.WriteString(".")
	if v := r.Verified(); v > 0 {
		b.WriteString(" ")
		b.WriteString(plural(v, "finding"))
		b.WriteString(" were independently verified (re-confirmed against the target).")
	}
	return b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return itoa(n) + " " + word + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
