package dalfox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// event mirrors the fields tsengine projects from dalfox's JSON output.
// dalfox emits either a JSON array or JSONL depending on flags; parseAny
// tolerates both shapes.
type event struct {
	Type       string `json:"type"` // "G" = grep, "R" = reflected, "V" = verified
	InjectType string `json:"inject_type"`
	Method     string `json:"method"`
	Data       string `json:"data"` // URL with injected payload
	Param      string `json:"param"`
	Payload    string `json:"payload"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
	Msg        string `json:"msg"`
}

// parseAny accepts either a JSON array (default dalfox --format json) or
// JSONL (one event per line). Picks whichever shape the blob has.
func parseAny(blob []byte) []types.SandboxEmittedFinding {
	trimmed := bytes.TrimSpace(blob)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		return parseArray(trimmed)
	}
	return parseJSONL(blob)
}

func parseArray(blob []byte) []types.SandboxEmittedFinding {
	var events []event
	if err := json.Unmarshal(blob, &events); err != nil {
		return nil
	}
	out := make([]types.SandboxEmittedFinding, 0, len(events))
	for _, ev := range events {
		if f, ok := toFinding(ev, nil); ok {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseJSONL(blob []byte) []types.SandboxEmittedFinding {
	var out []types.SandboxEmittedFinding
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if f, ok := toFinding(ev, line); ok {
			out = append(out, f)
		}
	}
	return out
}

func toFinding(ev event, raw []byte) (types.SandboxEmittedFinding, bool) {
	// dalfox can emit informational entries with no actionable payload;
	// skip those.
	if strings.TrimSpace(ev.Payload) == "" && strings.TrimSpace(ev.Type) == "" {
		return types.SandboxEmittedFinding{}, false
	}
	cwes := normalizeCWE(ev.CWE)
	rawCopy := []byte(nil)
	if raw != nil {
		rawCopy = make([]byte, len(raw))
		copy(rawCopy, raw)
	} else {
		// Synthesize raw from the structured event for the array path.
		if b, err := json.Marshal(ev); err == nil {
			rawCopy = b
		}
	}
	ruleID := "dalfox::" + classifyType(ev.Type)
	if ev.InjectType != "" {
		ruleID = "dalfox::" + classifyType(ev.Type) + "::" + ev.InjectType
	}
	return types.SandboxEmittedFinding{
		RuleID:          ruleID,
		Tool:            "dalfox",
		Severity:        normalizeSeverity(ev.Severity),
		CWE:             cwes,
		Endpoint:        ev.Data,
		Title:           title(ev),
		Description:     ev.Msg,
		RawOutput:       rawCopy,
		MITRETechniques: []string{"T1059.007"}, // command/script injection — JS XSS
		ToolArgs: map[string]string{
			"param":   ev.Param,
			"payload": ev.Payload,
			"method":  ev.Method,
		},
	}, true
}

func classifyType(t string) string {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "V":
		return "verified-xss"
	case "R":
		return "reflected-xss"
	case "G":
		return "grep-xss"
	case "":
		return "xss"
	default:
		return "xss-" + strings.ToLower(t)
	}
}

func title(ev event) string {
	if strings.TrimSpace(ev.Msg) != "" {
		return ev.Msg
	}
	switch strings.ToUpper(strings.TrimSpace(ev.Type)) {
	case "V":
		return "Verified XSS"
	case "R":
		return "Reflected XSS"
	case "G":
		return "Grep-flagged XSS pattern"
	}
	return "Dalfox XSS finding"
}

func normalizeSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	case "info", "informational", "":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// normalizeCWE accepts dalfox's "CWE-79" or "cwe-79" forms and returns a
// canonical single-element slice. Empty input → nil.
func normalizeCWE(c string) []string {
	c = strings.TrimSpace(c)
	if c == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(c), "cwe-") {
		c = "CWE-" + c[4:]
	}
	return []string{c}
}
