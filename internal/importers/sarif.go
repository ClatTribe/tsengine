// Package importers normalizes OTHER scanners' output (SARIF, Snyk, GitHub
// Dependabot) into the engine's contracts — a types.Scan (so report / findings DB /
// gate consume it for free) and reachability.SCAFinding (so dependency alerts flow
// through reachability triage). The multiplier: a customer who already runs
// Snyk/Semgrep/CodeQL can pipe results through tsengine's grounding + gate.
package importers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- SARIF 2.1.0 (GitHub code scanning / CodeQL / semgrep / many SAST tools) ---

type sarifDoc struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		SecuritySeverity string   `json:"security-severity"`
		Tags             []string `json:"tags"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// FromSARIF parses a SARIF 2.1.0 document into a types.Scan.
func FromSARIF(data []byte, target string, now time.Time) (types.Scan, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return types.Scan{}, fmt.Errorf("sarif: %w", err)
	}
	if len(doc.Runs) == 0 {
		return types.Scan{}, fmt.Errorf("sarif: no runs")
	}
	scan := newScan("repository", target, now)
	tools := map[string]bool{}
	n := 0
	for _, run := range doc.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = "sarif"
		}
		tools[tool] = true
		rules := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			n++
			rule := rules[res.RuleID]
			f := types.Finding{
				ID:              fmt.Sprintf("imp-%s-%04d", short(tool), n),
				RuleID:          tool + "::" + res.RuleID,
				Tool:            tool,
				Severity:        sarifSeverity(rule, res),
				Title:           firstNonEmpty(rule.ShortDescription.Text, res.Message.Text, res.RuleID),
				Description:     res.Message.Text,
				Endpoint:        sarifLoc(res),
				CWE:             cweFromTags(rule.Properties.Tags),
				DiscoveredAt:    now,
				DiscoveryMethod: &types.DiscoveryMethod{Primary: "imported:" + strings.ToLower(tool)},
			}
			scan.FindingsRaw = append(scan.FindingsRaw, f)
		}
	}
	scan.FindingsEnriched = scan.FindingsRaw
	for t := range tools {
		scan.AnchorsFired = append(scan.AnchorsFired, t)
	}
	return scan, nil
}

func sarifSeverity(rule sarifRule, res sarifResult) types.Severity {
	if rule.Properties.SecuritySeverity != "" {
		if cvss, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err == nil {
			return severityFromCVSS(cvss)
		}
	}
	lvl := res.Level
	if lvl == "" {
		lvl = rule.DefaultConfiguration.Level
	}
	switch strings.ToLower(lvl) {
	case "error":
		return types.SeverityHigh
	case "warning":
		return types.SeverityMedium
	case "note":
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func sarifLoc(res sarifResult) string {
	if len(res.Locations) == 0 {
		return ""
	}
	p := res.Locations[0].PhysicalLocation
	if p.ArtifactLocation.URI == "" {
		return ""
	}
	if p.Region.StartLine > 0 {
		return fmt.Sprintf("%s:%d", p.ArtifactLocation.URI, p.Region.StartLine)
	}
	return p.ArtifactLocation.URI
}

// cweFromTags extracts CWE ids from SARIF rule tags like "external/cwe/cwe-079".
func cweFromTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		l := strings.ToLower(t)
		if i := strings.LastIndex(l, "cwe-"); i >= 0 {
			num := strings.TrimLeft(l[i+4:], "0")
			if num == "" {
				num = "0"
			}
			if isDigits(num) {
				out = append(out, "CWE-"+num)
			}
		}
	}
	return out
}

func severityFromCVSS(c float64) types.Severity {
	switch {
	case c >= 9.0:
		return types.SeverityCritical
	case c >= 7.0:
		return types.SeverityHigh
	case c >= 4.0:
		return types.SeverityMedium
	case c > 0:
		return types.SeverityLow
	}
	return types.SeverityInfo
}
