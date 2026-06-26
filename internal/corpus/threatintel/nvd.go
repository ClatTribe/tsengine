package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// NVDURL is NVD's CVE API 2.0 endpoint. It's keyless (a key only raises the rate limit), and a refresh can
// page it or consume a mirrored bulk dump — either way the body is the same 2.0 JSON shape ParseNVD reads.
// Unlike KEV/EPSS (single small files), the full NVD is large + paginated, so the NVD fetch is best-effort and
// optional: it ENRICHES the KEV+EPSS corpus with CVSS base vectors, never blocks it (mirrors ExploitDB).
const NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDEntry is the CVSS data ParseNVD extracts for one CVE: the base score and the full base vector
// (AV/AC/PR/UI/S/C/I/A). The VECTOR is the value-add over the bare score the corpus already has a slot for —
// it lets enrichment reason about ATTACK VECTOR (network-reachable vs local), privileges required, and
// user-interaction, not just a single magnitude.
type NVDEntry struct {
	BaseScore float64
	Vector    string
}

// nvdDoc mirrors the relevant slice of NVD's CVE API 2.0 / bulk JSON. We read only id + the CVSS metrics,
// preferring v3.1 → v3.0 → v2 (newest scoring system available for that CVE).
type nvdDoc struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// ParseNVD reads an NVD CVE 2.0 JSON body into a CVE→NVDEntry map. A CVE with no CVSS metric block at all
// (reserved/rejected/awaiting-analysis) is skipped — we never invent a score (§10). Preference is the newest
// scoring system present: v3.1, else v3.0, else v2.
func ParseNVD(r io.Reader) (map[string]NVDEntry, error) {
	var doc nvdDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("threatintel: decode NVD JSON: %w", err)
	}
	out := make(map[string]NVDEntry, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVE.ID))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		m, ok := firstMetric(v.CVE.Metrics.V31, v.CVE.Metrics.V30, v.CVE.Metrics.V2)
		if !ok {
			continue // no CVSS metric → skip (don't fabricate)
		}
		out[id] = NVDEntry{BaseScore: m.CVSSData.BaseScore, Vector: strings.TrimSpace(m.CVSSData.VectorString)}
	}
	return out, nil
}

// firstMetric returns the first metric from the highest-preference non-empty list with a usable vector string.
func firstMetric(lists ...[]nvdMetric) (nvdMetric, bool) {
	for _, list := range lists {
		for _, m := range list {
			if strings.TrimSpace(m.CVSSData.VectorString) != "" {
				return m, true
			}
		}
	}
	return nvdMetric{}, false
}
