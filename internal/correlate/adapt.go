package correlate

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// FromScan adapts an L1 dashboard scan into a correlation Asset. Entity extraction
// reads title/description/endpoint + a slice of the raw tool output (secrets like
// leaked AWS keys often live there).
func FromScan(scan types.Scan) Asset {
	a := Asset{
		ID:     scan.ScanID,
		Type:   string(scan.Asset.Type),
		Target: scan.Asset.Target,
	}
	src := scan.FindingsEnriched
	if len(src) == 0 {
		src = scan.FindingsRaw
	}
	for _, f := range src {
		desc := f.Description
		if len(f.RawOutput) > 0 {
			raw := string(f.RawOutput)
			if len(raw) > 2000 {
				raw = raw[:2000]
			}
			desc = strings.TrimSpace(desc + " " + raw)
		}
		a.Findings = append(a.Findings, Finding{
			ID: f.ID, Title: firstNonEmpty(f.Title, f.RuleID), Severity: string(f.Severity),
			Endpoint: f.Endpoint, Tool: f.Tool, Description: desc,
			Verified: f.VerificationStatus == types.VerificationVerified,
		})
	}
	return a
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
