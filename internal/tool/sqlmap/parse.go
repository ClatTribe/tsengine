package sqlmap

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// parse extracts confirmed injection points from sqlmap's stdout report.
// sqlmap prints, per vulnerable parameter, a block like:
//
//	sqlmap identified the following injection point(s) ...
//	Parameter: cat (GET)
//	    Type: boolean-based blind
//	    Title: AND boolean-based blind - WHERE or HAVING clause
//	    Type: UNION query
//	    Title: Generic UNION query (NULL) - 3 columns
//
// We emit one CWE-89 finding per vulnerable Parameter, summarizing the
// detected injection types in the description. No "Parameter:" block →
// no findings (target not injectable).
func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var (
		out       []types.SandboxEmittedFinding
		curParam  string
		curMethod string
		types_    []string
	)

	flush := func() {
		if curParam == "" {
			return
		}
		title := fmt.Sprintf("SQL injection in parameter %q", curParam)
		desc := "sqlmap confirmed SQL injection"
		if len(types_) > 0 {
			desc = "sqlmap confirmed SQL injection (" + strings.Join(types_, "; ") + ")"
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "sqlmap::sqli",
			Tool:            "sqlmap",
			Severity:        types.SeverityHigh,
			CWE:             []string{"CWE-89"},
			Endpoint:        target,
			Title:           title,
			Description:     desc,
			RawOutput:       []byte(""),
			MITRETechniques: []string{"T1190"},
			ToolArgs:        map[string]string{"parameter": curParam, "method": curMethod},
		})
		curParam, curMethod, types_ = "", "", nil
	}

	sc := bufio.NewScanner(strings.NewReader(string(blob)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Parameter:"):
			flush() // close the previous parameter block
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Parameter:"))
			curParam, curMethod = splitParam(rest)
		case strings.HasPrefix(line, "Type:"):
			types_ = append(types_, strings.TrimSpace(strings.TrimPrefix(line, "Type:")))
		}
	}
	flush() // close the final block

	if len(out) == 0 {
		return nil
	}
	return out
}

// splitParam parses "cat (GET)" → ("cat", "GET").
func splitParam(s string) (name, method string) {
	if i := strings.Index(s, "("); i >= 0 {
		name = strings.TrimSpace(s[:i])
		method = strings.TrimSpace(strings.Trim(s[i:], "()"))
		return name, method
	}
	return strings.TrimSpace(s), ""
}
