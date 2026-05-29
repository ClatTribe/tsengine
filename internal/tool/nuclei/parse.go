package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// jsonlEvent mirrors the fields we consume from nuclei's -jsonl output.
// Only fields we actually project are declared; the rest is preserved via
// rawOutput.
type jsonlEvent struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
		Classification struct {
			CWEID     []string `json:"cwe-id"`
			CVEID     []string `json:"cve-id"`
			CVSSScore float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// parseJSONL turns nuclei's JSONL output into a slice of canonical
// SandboxEmittedFindings. Each line is one event. Bad lines are skipped
// (logged at caller) — we don't fail the whole batch because nuclei
// sometimes emits non-JSON status lines we want to ignore.
func parseJSONL(blob []byte) []types.SandboxEmittedFinding {
	var out []types.SandboxEmittedFinding
	sc := bufio.NewScanner(bytes.NewReader(blob))
	// nuclei output can be large per-line; bump the buffer.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev jsonlEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.TemplateID == "" {
			continue
		}
		out = append(out, eventToFinding(ev, line))
	}
	return out
}

func eventToFinding(ev jsonlEvent, raw []byte) types.SandboxEmittedFinding {
	endpoint := ev.MatchedAt
	if endpoint == "" {
		endpoint = ev.Host
	}
	cwes := normalizeCWE(ev.Info.Classification.CWEID)
	rawCopy := make([]byte, len(raw))
	copy(rawCopy, raw)
	return types.SandboxEmittedFinding{
		RuleID:      "nuclei::" + ev.TemplateID,
		Tool:        "nuclei",
		Severity:    normalizeSeverity(ev.Info.Severity),
		CWE:         cwes,
		Endpoint:    endpoint,
		Title:       firstNonEmpty(ev.Info.Name, ev.TemplateID),
		Description: ev.Info.Description,
		RawOutput:   rawCopy,
		// nuclei templates conventionally tagged with the recon/probe
		// activity; we map the broad initial-access bucket here. Real
		// ATT&CK technique mapping per-template is a Phase 4 enrichment
		// concern, not a parser concern.
		MITRETechniques: []string{"T1595"},
	}
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

// normalizeCWE rewrites nuclei's "cwe-89" lowercase form to canonical
// "CWE-89". Duplicates are dropped while preserving first-seen order.
func normalizeCWE(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// nuclei emits e.g. "cwe-89" — canonicalize.
		if strings.HasPrefix(strings.ToLower(c), "cwe-") {
			c = "CWE-" + c[4:]
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
