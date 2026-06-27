package opencre

import (
	"strings"
	"testing"
)

// A representative OpenCRE /rest/v1/standard/CWE page (the verified shape): CWE-319 links to two CRE nodes,
// CWE-79 to one; a non-CRE link is ignored.
const fixture = `{
  "page": 1,
  "total_pages": 1,
  "standards": [
    {"sectionID": "319", "links": [
      {"ltype": "Linked To", "document": {"doctype": "CRE", "id": "462-245", "name": "Encrypt data in transit"}},
      {"ltype": "Automatically linked to", "document": {"doctype": "CRE", "id": "133-219", "name": "Use TLS"}},
      {"ltype": "Linked To", "document": {"doctype": "Standard", "id": "x", "name": "not a CRE"}}
    ]},
    {"sectionID": "79", "links": [
      {"ltype": "Linked To", "document": {"doctype": "CRE", "id": "616-305", "name": "Encode output"}}
    ]}
  ]
}`

func TestParseStandard_KeepsOnlyCRELinksKeyedByCWE(t *testing.T) {
	m, err := ParseStandard(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("ParseStandard: %v", err)
	}
	if got := m["CWE-319"]; len(got) != 2 {
		t.Errorf("CWE-319 should have 2 CRE links (non-CRE ignored), got %d: %+v", len(got), got)
	}
	if got := m["CWE-79"]; len(got) != 1 || got[0].ID != "616-305" {
		t.Errorf("CWE-79 CRE link wrong: %+v", got)
	}
}

func TestCrossReference_ReportsBackedVsInHouseOnly(t *testing.T) {
	openCRE, _ := ParseStandard(strings.NewReader(fixture))
	// Our crosswalk has 319 + 79 (OpenCRE-backed) and 1004 (HttpOnly cookie — OpenCRE has no nexus here).
	rep := CrossReference([]string{"CWE-319", "CWE-79", "CWE-1004"}, openCRE)
	if rep.TotalMapped != 3 {
		t.Fatalf("TotalMapped want 3, got %d", rep.TotalMapped)
	}
	if len(rep.OpenCREBacked) != 2 {
		t.Errorf("want 2 OpenCRE-backed, got %v", rep.OpenCREBacked)
	}
	if len(rep.InHouseOnly) != 1 || rep.InHouseOnly[0] != "CWE-1004" {
		t.Errorf("CWE-1004 should be in-house-only, got %v", rep.InHouseOnly)
	}
	if rep.BackedPercent != 66 {
		t.Errorf("backed percent want 66, got %d", rep.BackedPercent)
	}
}

func TestParseStandard_MalformedErrors(t *testing.T) {
	if _, err := ParseStandard(strings.NewReader("not json")); err == nil {
		t.Error("malformed JSON should error")
	}
}
