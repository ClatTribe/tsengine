package threatintel

import (
	"strings"
	"testing"
	"time"
)

// A representative NVD CVE 2.0 body: one CVE with a v3.1 metric, one with only v2 (fallback), and one
// reserved CVE with no metric block (must be skipped — never fabricate a score).
const nvdFixture = `{
  "vulnerabilities": [
    {"cve": {"id": "CVE-2021-44228", "metrics": {"cvssMetricV31": [
      {"cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0}}]}}},
    {"cve": {"id": "CVE-2014-0160", "metrics": {"cvssMetricV2": [
      {"cvssData": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N", "baseScore": 5.0}}]}}},
    {"cve": {"id": "CVE-2099-0001", "metrics": {}}}
  ]
}`

func TestParseNVD_ExtractsVectorPrefersV31SkipsEmpty(t *testing.T) {
	m, err := ParseNVD(strings.NewReader(nvdFixture))
	if err != nil {
		t.Fatalf("ParseNVD: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("want 2 scored CVEs (reserved one skipped), got %d: %+v", len(m), m)
	}
	log4j := m["CVE-2021-44228"]
	if log4j.BaseScore != 10.0 || !strings.HasPrefix(log4j.Vector, "CVSS:3.1/AV:N") {
		t.Errorf("v3.1 metric not extracted: %+v", log4j)
	}
	hb := m["CVE-2014-0160"]
	if hb.Vector != "AV:N/AC:L/Au:N/C:P/I:N/A:N" {
		t.Errorf("v2 fallback vector not extracted: %+v", hb)
	}
	if _, ok := m["CVE-2099-0001"]; ok {
		t.Error("a CVE with no CVSS metric must be skipped, not fabricated")
	}
}

// Build threads NVD vectors into entries: populates the CVSS base score (KEV/EPSS don't carry one) + the
// vector, and counts them in the manifest.
func TestBuild_MergesNVDVectors(t *testing.T) {
	cvss := map[string]NVDEntry{
		"CVE-2021-44228": {BaseScore: 10.0, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
	}
	entries, m := Build(nil, time.Time{}, "test", nil, time.Time{}, nil, cvss)
	e := entries["CVE-2021-44228"]
	if e.CVSS != 10.0 || !strings.Contains(e.CVSSVector, "AV:N") {
		t.Errorf("NVD entry not merged: %+v", e)
	}
	if m.CVSSCount != 1 {
		t.Errorf("manifest CVSSCount want 1, got %d", m.CVSSCount)
	}
}
