package cloudtocode

import (
	"encoding/json"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Annotate links each cloud finding in findings to its IaC source (setting
// CodeProvenance in place) using the resource index. Returns the number of
// findings that got a grounded link. Findings that aren't cloud findings, or
// that have no confident source, are left untouched.
//
// This is the top-level Cloud-to-Code entry point: index the IaC tree with
// IndexDir, then Annotate the scan's findings.
func Annotate(findings []types.Finding, idx []Resource) int {
	if len(idx) == 0 {
		return 0
	}
	linked := 0
	for i := range findings {
		cf, ok := cloudFindingFrom(findings[i])
		if !ok {
			continue
		}
		if prov := match(cf, idx); prov != nil {
			findings[i].CodeProvenance = prov
			linked++
		}
	}
	return linked
}

// AnnotateDir is the convenience wrapper: index iacRoot and annotate findings.
func AnnotateDir(findings []types.Finding, iacRoot string) (int, error) {
	idx, err := IndexDir(iacRoot)
	if err != nil {
		return 0, err
	}
	return Annotate(findings, idx), nil
}

// cloudFindingFrom projects a prowler finding into the matcher's input. Returns
// ok=false for non-cloud findings. The check id, physical name, ARN, and type
// come from the OCSF raw output when present, falling back to the rule id and
// the "<Type> <Name> @<Region>" endpoint shape the prowler wrapper emits.
func cloudFindingFrom(f types.Finding) (CloudFinding, bool) {
	if f.Tool != "prowler" && !strings.HasPrefix(f.RuleID, "prowler::") {
		return CloudFinding{}, false
	}

	cf := CloudFinding{}
	cf.CheckID = f.ToolArgs["check_id"]
	if cf.CheckID == "" {
		cf.CheckID = strings.TrimPrefix(f.RuleID, "prowler::")
	}

	// Prefer the structured OCSF resource when it survived into raw_output.
	if len(f.RawOutput) > 0 {
		var ocsf struct {
			Resources []struct {
				UID  string `json:"uid"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"resources"`
		}
		if json.Unmarshal(f.RawOutput, &ocsf) == nil && len(ocsf.Resources) > 0 {
			r := ocsf.Resources[0]
			cf.Resource = r.Name
			cf.ARN = r.UID
			cf.Type = r.Type
		}
	}

	// Fallback: parse the endpoint "<Type> <Name> @<Region>".
	if cf.Resource == "" {
		t, n := parseEndpoint(f.Endpoint)
		cf.Type = firstNonEmpty(cf.Type, t)
		cf.Resource = n
	}

	if cf.Resource == "" && cf.ARN == "" {
		return CloudFinding{}, false // nothing to match on
	}
	return cf, true
}

// parseEndpoint splits the prowler endpoint shape "<Type> <Name> @<Region>"
// into (type, name). Region (after " @") is dropped.
func parseEndpoint(ep string) (resType, name string) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return "", ""
	}
	if i := strings.Index(ep, " @"); i >= 0 {
		ep = ep[:i]
	}
	parts := strings.SplitN(strings.TrimSpace(ep), " ", 2)
	if len(parts) == 2 {
		return parts[0], strings.TrimSpace(parts[1])
	}
	return "", parts[0]
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
