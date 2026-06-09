// Package exporter is the OUTBOUND handoff (roadmap §9): it emits tsengine's
// proven, prioritized findings into the systems a customer already runs. SARIF so
// GitHub code-scanning / any SARIF consumer shows the findings inline on the PR; a
// signed finding/case webhook so a SIEM / SOC / AI-SOC / ticketing system can ingest
// them. The mirror of internal/importers — tsengine becomes a finding SOURCE, not
// just a sink.
package exporter

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/report"
)

// --- SARIF 2.1.0 export ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	Help             *sarifText     `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// ToSARIF renders a report as a SARIF 2.1.0 log. One rule per distinct finding
// class (slugged from the title); each finding becomes a result. `security-severity`
// and `tags` (incl. CWE) drive GitHub code-scanning's severity + grouping; the
// tsengine status (verified/reachable) rides in result properties.
func ToSARIF(r *report.Report) ([]byte, error) {
	rules := map[string]sarifRule{}
	var results []sarifResult

	for _, f := range r.Findings {
		ruleID := "tsengine/" + slug(f.Title)
		if _, ok := rules[ruleID]; !ok {
			tags := []string{"security"}
			for _, c := range f.CWE {
				tags = append(tags, "external/cwe/"+strings.ToLower(c))
			}
			rules[ruleID] = sarifRule{
				ID: ruleID, Name: f.Title,
				ShortDescription: sarifText{Text: f.Title},
				DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
				Properties: map[string]any{
					"security-severity": securitySeverity(f.Severity),
					"tags":              tags,
				},
			}
			if f.Remediation != "" {
				h := sarifText{Text: f.Remediation}
				rl := rules[ruleID]
				rl.Help = &h
				rules[ruleID] = rl
			}
		}

		res := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: messageFor(f)},
			Properties: map[string]any{
				"tsengine/status":   nz(f.Status, "pattern_match"),
				"tsengine/severity": f.Severity,
			},
		}
		if f.Tool != "" {
			res.Properties["tsengine/tool"] = f.Tool
		}
		if loc := locationFor(f.Endpoint); loc != nil {
			res.Locations = []sarifLocation{*loc}
		}
		results = append(results, res)
	}

	// deterministic rule order
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rl := range rules {
		ruleList = append(ruleList, rl)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tsengine",
				InformationURI: "https://github.com/ClatTribe/tsengine",
				Version:        r.Engine,
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	}
	return "note"
}

// securitySeverity maps our band to a CVSS-style number GitHub uses to color/sort.
func securitySeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	}
	return "0.0"
}

func messageFor(f report.Finding) string {
	m := f.Description
	if m == "" {
		m = f.Title
	}
	if f.Status == "verified" {
		m = "[verified] " + m
	}
	return m
}

// locationFor turns an endpoint into a SARIF location. A "file:line" endpoint
// (SAST/SCA) maps to a region; a URL or bare host maps to a uri-only location.
func locationFor(endpoint string) *sarifLocation {
	if endpoint == "" {
		return nil
	}
	uri := endpoint
	var region *sarifRegion
	if i := strings.LastIndex(endpoint, ":"); i > 0 && !strings.Contains(endpoint[:i], "://") {
		if line := atoiSafe(endpoint[i+1:]); line > 0 {
			uri = endpoint[:i]
			region = &sarifRegion{StartLine: line}
		}
	}
	return &sarifLocation{PhysicalLocation: sarifPhysical{
		ArtifactLocation: sarifArtifact{URI: uri},
		Region:           region,
	}}
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "finding"
	}
	return out
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
