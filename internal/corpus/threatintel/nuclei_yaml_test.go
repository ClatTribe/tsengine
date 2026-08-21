package threatintel

import (
	"reflect"
	"testing"
)

// A realistic modern nuclei CVE template exercises: CSV tags, classification.cwe-id, a POST with a
// block-scalar body, header map, compact sequence-of-mappings matchers, a flow-style word list, a
// status list, matchers-condition, an inline comment, and a negative matcher.
const modernTemplate = `id: CVE-2023-1234

info:
  name: Example Product - Remote Code Execution
  author: pdteam
  severity: critical
  description: |
    A crafted request reaches an eval sink.
    Two lines to prove block-scalar consumption does not desync the parse.
  reference:
    - https://example.com/advisory
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cwe-id: CWE-94
  tags: cve,cve2023,rce,example   # trailing comment must be stripped

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/run?debug=1"
      - "{{BaseURL}}/api/run2"
    headers:
      Content-Type: application/json
    body: |
      {"tpl":"{{7*7}}"}
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words: ["49"]
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "error"
        negative: true
`

func TestDecodeNucleiTemplate_Modern(t *testing.T) {
	doc, ok := DecodeNucleiTemplate([]byte(modernTemplate))
	if !ok {
		t.Fatal("expected ok")
	}
	if doc.ID != "CVE-2023-1234" {
		t.Errorf("ID = %q", doc.ID)
	}
	if doc.Info.Name != "Example Product - Remote Code Execution" {
		t.Errorf("Name = %q", doc.Info.Name)
	}
	if doc.Info.Severity != "critical" {
		t.Errorf("Severity = %q", doc.Info.Severity)
	}
	if !reflect.DeepEqual(doc.Info.Tags, []string{"cve", "cve2023", "rce", "example"}) {
		t.Errorf("Tags = %#v", doc.Info.Tags)
	}
	if !reflect.DeepEqual(doc.Info.CWE, []string{"CWE-94"}) {
		t.Errorf("CWE = %#v", doc.Info.CWE)
	}
	if len(doc.HTTP) != 1 {
		t.Fatalf("HTTP blocks = %d, want 1", len(doc.HTTP))
	}
	req := doc.HTTP[0]
	if req.Method != "POST" {
		t.Errorf("Method = %q", req.Method)
	}
	if !reflect.DeepEqual(req.Path, []string{"{{BaseURL}}/api/run?debug=1", "{{BaseURL}}/api/run2"}) {
		t.Errorf("Path = %#v", req.Path)
	}
	if req.Headers["Content-Type"] != "application/json" {
		t.Errorf("Headers = %#v", req.Headers)
	}
	if req.Body != `{"tpl":"{{7*7}}"}` {
		t.Errorf("Body = %q", req.Body)
	}
	if req.MatchersCondition != "and" {
		t.Errorf("MatchersCondition = %q", req.MatchersCondition)
	}
	if len(req.Matchers) != 3 {
		t.Fatalf("matchers = %d, want 3", len(req.Matchers))
	}
	if req.Matchers[0].Type != "word" || !reflect.DeepEqual(req.Matchers[0].Words, []string{"49"}) {
		t.Errorf("matcher0 = %#v", req.Matchers[0])
	}
	if req.Matchers[1].Type != "status" || !reflect.DeepEqual(req.Matchers[1].Status, []int{200}) {
		t.Errorf("matcher1 = %#v", req.Matchers[1])
	}
	if req.Matchers[2].Type != "word" || !req.Matchers[2].Negative {
		t.Errorf("matcher2 negative not decoded: %#v", req.Matchers[2])
	}
}

// End-to-end: the decoder feeds the pure mapping core and yields the same record the ADR promises —
// a request skeleton (primary) with the single-word-on-body matcher mapped to a `contains` candidate
// and everything else reference-only.
func TestDecodeThenRecord_EndToEnd(t *testing.T) {
	doc, ok := DecodeNucleiTemplate([]byte(modernTemplate))
	if !ok {
		t.Fatal("decode failed")
	}
	rec, ok := RecordFromNucleiTemplate(doc, doc.ID, "http/cves/2023/CVE-2023-1234.yaml")
	if !ok {
		t.Fatal("record build failed")
	}
	if rec.CVE != "CVE-2023-1234" || rec.Source != "nuclei" {
		t.Errorf("provenance: %+v", rec)
	}
	if rec.Class != "rce" {
		t.Errorf("class = %q, want rce", rec.Class)
	}
	if len(rec.Probes) != 2 {
		t.Fatalf("probes = %d, want 2 (one per path)", len(rec.Probes))
	}
	if rec.Probes[0].Method != "POST" || rec.Probes[0].Body != `{"tpl":"{{7*7}}"}` {
		t.Errorf("probe0 = %+v", rec.Probes[0])
	}
	// The word list ["49"] is multi-condition-guarded by matchers-condition:and with a status +
	// a negative word, but mapNucleiMatcher only maps a single positive word-on-body: the FIRST
	// req matcher that qualifies. Here matcher0 is exactly that, so it maps.
	if rec.Predicate != "contains" || rec.Args["marker"] != "49" {
		t.Errorf("predicate=%q args=%v, want contains/49", rec.Predicate, rec.Args)
	}
}

// Legacy `requests:` spelling + a version-fingerprint word (which must NOT become a predicate).
func TestDecodeNucleiTemplate_LegacyRequestsAndFingerprint(t *testing.T) {
	tmpl := `id: CVE-2019-0001
info:
  name: Old Thing
  severity: high
  tags: cve,tech
requests:
  - method: GET
    path:
      - '{{BaseURL}}/version'
    matchers:
      - type: word
        words:
          - "Server: OldThing/1.0"
          - "X-Powered-By"
`
	doc, ok := DecodeNucleiTemplate([]byte(tmpl))
	if !ok {
		t.Fatal("legacy decode failed")
	}
	if len(doc.HTTP) != 1 || doc.HTTP[0].Method != "GET" {
		t.Fatalf("legacy requests block not decoded: %#v", doc.HTTP)
	}
	rec, ok := RecordFromNucleiTemplate(doc, doc.ID, "x.yaml")
	if !ok {
		t.Fatal("record failed")
	}
	// Multi-word matcher is ambiguous (AND/OR) → reference-only, never a predicate.
	if rec.Predicate != "" {
		t.Errorf("multi-word fingerprint mapped to a predicate: %q", rec.Predicate)
	}
	if rec.Matcher == "" {
		t.Error("matcher reference text must be preserved")
	}
}

// A template with no request block (matcher-less / info-only / raw-only) yields no skeleton and is
// refused upstream — never a hollow record.
func TestDecodeNucleiTemplate_NoHTTPRefusedDownstream(t *testing.T) {
	tmpl := `id: CVE-2020-9999
info:
  name: Info only
  severity: low
  tags: cve
`
	doc, ok := DecodeNucleiTemplate([]byte(tmpl))
	if !ok {
		t.Fatal("info-only template should still decode (has id)")
	}
	if _, ok := RecordFromNucleiTemplate(doc, doc.ID, "x.yaml"); ok {
		t.Fatal("a template with no request must be refused by RecordFromNucleiTemplate")
	}
}

// Junk / non-template input decodes to not-ok rather than panicking.
func TestDecodeNucleiTemplate_Junk(t *testing.T) {
	for _, in := range []string{"", "   ", "not yaml at all", "- just\n- a\n- list\n", "42"} {
		if _, ok := DecodeNucleiTemplate([]byte(in)); ok {
			t.Errorf("junk %q decoded ok", in)
		}
	}
}
