package prowler

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// ocsfFinding mirrors the subset of prowler's OCSF output we project.
// prowler emits an array of OCSF detection findings.
type ocsfFinding struct {
	StatusCode  string `json:"status_code"` // "PASS" | "FAIL" | "MANUAL"
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	FindingInfo struct {
		Title string `json:"title"`
		UID   string `json:"uid"`
	} `json:"finding_info"`
	Resources []struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Region string `json:"region"`
		Type   string `json:"type"`
	} `json:"resources"`
	Unmapped struct {
		CheckID string `json:"check_id"`
	} `json:"unmapped"`
}

// parseOCSF flattens prowler OCSF findings, keeping only FAIL results
// (PASS = the control held; not a finding to surface).
func parseOCSF(blob []byte) []types.SandboxEmittedFinding {
	blob = bytes.TrimSpace(blob)
	if len(blob) == 0 || blob[0] != '[' {
		return nil
	}
	var items []ocsfFinding
	if json.Unmarshal(blob, &items) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, it := range items {
		if !strings.EqualFold(it.StatusCode, "FAIL") {
			continue
		}
		raw, _ := json.Marshal(it)
		endpoint := ""
		if len(it.Resources) > 0 {
			r := it.Resources[0]
			endpoint = strings.TrimSpace(r.Type + " " + r.Name + " @" + r.Region)
		}
		rule := it.Unmapped.CheckID
		if rule == "" {
			rule = it.FindingInfo.UID
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "prowler::" + rule,
			Tool:            "prowler",
			Severity:        normalizeSeverity(it.Severity),
			Endpoint:        endpoint,
			Title:           firstNonEmpty(it.FindingInfo.Title, it.Message),
			Description:     it.Message,
			RawOutput:       raw,
			MITRETechniques: []string{"T1530"},
			ToolArgs:        map[string]string{"check_id": rule},
		})
	}
	return out
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
	default:
		return types.SeverityInfo
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
