package threatintel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// realRecord is the CISA-ADP container of CVE-2024-1000, copied from the live repository rather than
// invented. The shape that matters and would be easy to get wrong: options is an ARRAY OF
// SINGLE-KEY OBJECTS, and the file also carries a "CVE" ADP container from the CNA which must not be
// credited to CISA.
const realRecord = `{"containers":{"adp":[
 {"providerMetadata":{"shortName":"CVE"},"metrics":[{"other":{"type":"ssvc","content":{"id":"CVE-2024-1000","options":[{"Exploitation":"active"}]}}}]},
 {"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{
   "id":"CVE-2024-1000","role":"CISA Coordinator","version":"2.0.3",
   "options":[{"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"total"}]}}}]}
]}}`

func tgz(t *testing.T, files map[string]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return bytes.NewReader(buf.Bytes())
}

func TestParseVulnrichment_ReadsCISAsDecisionPoints(t *testing.T) {
	got, err := ParseVulnrichment(tgz(t, map[string]string{
		"vulnrichment-develop/2024/1xxx/CVE-2024-1000.json": realRecord,
	}))
	if err != nil {
		t.Fatal(err)
	}
	s := got["CVE-2024-1000"]
	if s == nil {
		t.Fatal("the CISA-ADP SSVC record was not read")
	}
	// From the CISA-ADP container, NOT the CNA one — which says "active" for the same CVE.
	// Crediting the CNA's judgement to CISA would attribute someone else's assessment to the
	// authority, which is the whole reason the provider is checked.
	if s.Exploitation != "none" {
		t.Errorf("Exploitation = %q, want CISA's \"none\" rather than the CNA container's \"active\"", s.Exploitation)
	}
	if s.Automatable != "no" {
		t.Errorf("Automatable = %q — the decision point no other feed provides", s.Automatable)
	}
	if s.TechnicalImpact != "total" {
		t.Errorf("Technical Impact = %q (note the SPACE in the published key)", s.TechnicalImpact)
	}
}

// A record with no recognised decision point is not an assessment. Returning an empty struct would
// put "CISA assessed this" against nothing.
func TestParseVulnrichment_NoDecisionPointsIsNotAnAssessment(t *testing.T) {
	got, err := ParseVulnrichment(tgz(t, map[string]string{
		"x/CVE-2024-2000.json": `{"containers":{"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},
			"metrics":[{"other":{"type":"ssvc","content":{"id":"CVE-2024-2000","options":[{"Unknown":"x"}]}}}]}]}}`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2024-2000"] != nil {
		t.Error("an empty assessment must not be recorded as one")
	}
}

// Files that are not CVE records, and records we cannot decode, are skipped rather than guessed at.
func TestParseVulnrichment_SkipsWhatItCannotRead(t *testing.T) {
	got, err := ParseVulnrichment(tgz(t, map[string]string{
		"vulnrichment-develop/README.md":          "not json",
		"vulnrichment-develop/CVE-bad.json":       "{{{",
		"vulnrichment-develop/CVE-2024-1000.json": realRecord,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-2024-1000"] == nil {
		t.Errorf("want exactly the one readable CVE record, got %d", len(got))
	}
}

// SSVC must survive the corpus FILE, not just the parser.
//
// A NOTE ON WHAT THIS DOES AND DOES NOT CATCH, because the obvious claim is wrong. Entry.
// NucleiTemplate once stayed empty forever from a missing json tag, and the instinct is that this
// test guards the same thing. It does not: Go marshals an untagged field under its NAME and
// unmarshals case-insensitively, so SSVC round-trips with or without the tag. The nuclei bug was
// asymmetric — the file was written elsewhere with an UNDERSCORE key, which case-insensitivity
// cannot bridge — and only asymmetric fields are exposed that way.
//
// What this does pin is that the value survives Write and read back intact, which is the property
// the dashboard contract depends on. Verified by mutating: removing the tag does NOT fail it, and
// saying so is better than implying a guard that is not there.
func TestSSVCSurvivesTheCorpusFile(t *testing.T) {
	entries, m := Build(Sources{
		SSVC: map[string]*types.SSVC{
			"CVE-2024-1000": {Exploitation: "none", Automatable: "no", TechnicalImpact: "total"},
		},
	})
	if m.SSVCCount != 1 {
		t.Errorf("manifest ssvc_count = %d, want 1 — a reader cannot see a feed's reach without it", m.SSVCCount)
	}

	dir := t.TempDir()
	path, err := Write(dir, entries, m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]Entry
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	got := back["CVE-2024-1000"].SSVC
	if got == nil {
		t.Fatal("SSVC did not survive the corpus file")
	}
	if got.Automatable != "no" || got.Exploitation != "none" || got.TechnicalImpact != "total" {
		t.Errorf("decision points changed across the file: %+v", got)
	}
}

// The corpus works without the feed. It is opt-in, and its absence must leave the other six
// untouched rather than producing an empty assessment against every CVE.
func TestBuild_WithoutVulnrichmentCarriesNoSSVC(t *testing.T) {
	entries, m := Build(Sources{KEV: map[string]types.KEVStatus{"CVE-2021-44228": {Listed: true}}})
	if m.SSVCCount != 0 {
		t.Errorf("no feed configured, so no assessments: got %d", m.SSVCCount)
	}
	if e := entries["CVE-2021-44228"]; e.SSVC != nil {
		t.Error("an absent feed must not put an empty assessment against a CVE")
	}
}
