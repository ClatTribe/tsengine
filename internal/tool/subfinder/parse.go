package subfinder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// event mirrors subfinder's JSONL output. Each line is one discovered
// subdomain + its source.
type event struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	Input  string `json:"input"`
}

// parseJSONL turns subfinder output into one finding per subdomain. The
// domain Handler treats these as recon artifacts (info severity) — they
// are surfaced for the security-engineer audience so they know the
// attack surface, not as vulnerabilities per se.
func parseJSONL(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []types.SandboxEmittedFinding
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 8*1024), 64*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(ev.Host))
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}

		rawCopy := make([]byte, len(line))
		copy(rawCopy, line)
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "subfinder::subdomain-found",
			Tool:            "subfinder",
			Severity:        types.SeverityInfo,
			Endpoint:        host,
			Title:           "Subdomain discovered: " + host,
			Description:     "via source: " + ev.Source,
			RawOutput:       rawCopy,
			MITRETechniques: []string{"T1590.005"}, // gather victim DNS info
			ToolArgs: map[string]string{
				"input":  ev.Input,
				"source": ev.Source,
			},
		})
	}
	return out
}
