package semgrep

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// output mirrors the subset of `semgrep --json` we project.
type output struct {
	Results []result `json:"results"`
}

type result struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   position `json:"start"`
	End     position `json:"end"`
	Extra   extra    `json:"extra"`
}

type position struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type extra struct {
	Message  string   `json:"message"`
	Severity string   `json:"severity"`
	Metadata metadata `json:"metadata"`
}

type metadata struct {
	// semgrep CWE entries look like "CWE-79: Improper Neutralization..."
	CWE  json.RawMessage `json:"cwe"`
	OWASP json.RawMessage `json:"owasp"`
}

var cwePattern = regexp.MustCompile(`CWE-\d+`)

func parse(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var o output
	if json.Unmarshal(blob, &o) != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(o.Results))
	for _, r := range o.Results {
		raw, _ := json.Marshal(r)
		endpoint := r.Path
		if r.Start.Line > 0 {
			endpoint = fmt.Sprintf("%s:%d", r.Path, r.Start.Line)
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "semgrep::" + r.CheckID,
			Tool:            "semgrep",
			Severity:        normalizeSeverity(r.Extra.Severity),
			CWE:             extractCWEs(r.Extra.Metadata.CWE),
			Endpoint:        endpoint,
			Title:           ruleTitle(r),
			Description:     r.Extra.Message,
			RawOutput:       raw,
			MITRETechniques: []string{"T1059"},
			ToolArgs:        map[string]string{"check_id": r.CheckID, "file": r.Path},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeSeverity maps semgrep's ERROR/WARNING/INFO to the canonical
// ladder.
func normalizeSeverity(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "CRITICAL":
		return types.SeverityHigh
	case "WARNING":
		return types.SeverityMedium
	case "INFO":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// extractCWEs pulls "CWE-N" tokens from semgrep's metadata.cwe, which
// may be a string or an array of strings.
func extractCWEs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	matches := cwePattern.FindAllString(string(raw), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

// ruleTitle uses the last dotted segment of the check_id as a short
// human title (semgrep check_ids are long dotted paths).
func ruleTitle(r result) string {
	id := r.CheckID
	if i := strings.LastIndex(id, "."); i >= 0 && i < len(id)-1 {
		id = id[i+1:]
	}
	return strings.ReplaceAll(id, "-", " ")
}
