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

// Regression: OpenCRE began serializing `page` as a STRING while `total_pages` stayed a
// number. The struct required both to be ints, so page 1 failed to decode — and because a
// page-1 failure is a hard error, `tsengine corpus compliance-provenance` reported nothing
// at all while still exiting 0. This pins the live shape (string page + numeric total_pages)
// and the reverse, so the lane cannot be silently killed by that drift again.
func TestParseStandard_TolerateStringOrNumericPaging(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"string page, numeric total (the live shape)",
			`{"page":"1","total_pages":48,"standards":[{"sectionID":"16","links":[{"ltype":"Linked To","document":{"doctype":"CRE","id":"462-245","name":"Remove unnecessary elements"}}]}]}`},
		{"numeric page, string total (the reverse flip)",
			`{"page":1,"total_pages":"48","standards":[{"sectionID":"16","links":[{"ltype":"Linked To","document":{"doctype":"CRE","id":"462-245","name":"Remove unnecessary elements"}}]}]}`},
		{"both numeric (the original shape)",
			`{"page":1,"total_pages":48,"standards":[{"sectionID":"16","links":[{"ltype":"Linked To","document":{"doctype":"CRE","id":"462-245","name":"Remove unnecessary elements"}}]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseStandard(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("decode failed (the lane would report nothing): %v", err)
			}
			if len(m["CWE-16"]) != 1 || m["CWE-16"][0].ID != "462-245" {
				t.Fatalf("CWE-16 not linked as expected: %+v", m)
			}
		})
	}
}

// Paging must still be driven by total_pages after the type change — otherwise Fetch would
// read one page of 48 and quietly under-report the corroboration number.
func TestDecodedTotalPagesDrivesTheWalk(t *testing.T) {
	p, err := decodePage(strings.NewReader(`{"page":"3","total_pages":"48","standards":[]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if int(p.TotalPages) != 48 || int(p.Page) != 3 {
		t.Fatalf("want page 3 of 48, got page %d of %d", int(p.Page), int(p.TotalPages))
	}
}
