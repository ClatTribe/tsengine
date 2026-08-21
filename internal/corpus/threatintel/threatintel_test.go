package threatintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const kevFixture = `{
  "catalogVersion": "2026.05.29",
  "dateReleased": "2026-05-29T08:00:00.000Z",
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
    {"cveID": "CVE-2017-5638", "dateAdded": "2017-03-10"}
  ]
}`

const epssFixture = `#model_version:v2025.03.14,score_date:2026-05-29T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.97426,0.99979
CVE-2014-0160,0.94400,0.99900
`

func TestParseKEV(t *testing.T) {
	kev, asOf, ver, err := ParseKEV(strings.NewReader(kevFixture))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if ver != "2026.05.29" {
		t.Errorf("catalog version = %q", ver)
	}
	if asOf.Year() != 2026 || asOf.Month() != 5 {
		t.Errorf("dateReleased not parsed: %v", asOf)
	}
	st, ok := kev["CVE-2021-44228"]
	if !ok || !st.Listed {
		t.Fatalf("Log4Shell should be listed: %+v", st)
	}
	if st.DateAdded.Year() != 2021 {
		t.Errorf("dateAdded not parsed: %v", st.DateAdded)
	}
}

func TestParseEPSS(t *testing.T) {
	epss, asOf, err := ParseEPSS(strings.NewReader(epssFixture))
	if err != nil {
		t.Fatalf("ParseEPSS: %v", err)
	}
	if len(epss) != 2 {
		t.Fatalf("want 2 rows, got %d", len(epss))
	}
	e := epss["CVE-2021-44228"]
	if e.Score < 0.97 || e.Percentile < 0.99 {
		t.Errorf("EPSS row mis-parsed: %+v", e)
	}
	if asOf.Year() != 2026 || !e.AsOf.Equal(asOf) {
		t.Errorf("score_date not applied: asOf=%v rowAsOf=%v", asOf, e.AsOf)
	}
}

func TestParseEPSSGzip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(epssFixture))
	_ = gz.Close()
	epss, _, err := ParseEPSSGzip(&buf)
	if err != nil {
		t.Fatalf("ParseEPSSGzip: %v", err)
	}
	if len(epss) != 2 {
		t.Errorf("want 2 rows from gzip, got %d", len(epss))
	}
}

func TestBuild_UnionsKEVAndEPSS(t *testing.T) {
	kev, kevAsOf, kevVer, _ := ParseKEV(strings.NewReader(kevFixture))
	epss, epssAsOf, _ := ParseEPSS(strings.NewReader(epssFixture))
	entries, m := Build(kev, kevAsOf, kevVer, epss, epssAsOf, nil, nil, nil, nil)

	// Union: 44228 (both), 5638 (kev only), 0160 (epss only) = 3.
	if len(entries) != 3 {
		t.Fatalf("union size = %d, want 3", len(entries))
	}
	both := entries["CVE-2021-44228"]
	if both.KEV == nil || !both.KEV.Listed || both.EPSS == nil {
		t.Errorf("Log4Shell should carry BOTH KEV + EPSS: %+v", both)
	}
	if entries["CVE-2017-5638"].EPSS != nil {
		t.Error("5638 is KEV-only; should have no EPSS")
	}
	if entries["CVE-2014-0160"].KEV != nil {
		t.Error("0160 is EPSS-only; should have no KEV")
	}
	if m.KEVCount != 2 || m.EPSSCount != 2 || m.EntryCount != 3 {
		t.Errorf("manifest counts wrong: %+v", m)
	}
	if !strings.Contains(m.Version, "kev-2026.05.29") || !strings.Contains(m.Version, "epss-2026-05-29") {
		t.Errorf("version string = %q", m.Version)
	}
}

func TestWriteAndLoadManifest(t *testing.T) {
	kev, kevAsOf, kevVer, _ := ParseKEV(strings.NewReader(kevFixture))
	epss, epssAsOf, _ := ParseEPSS(strings.NewReader(epssFixture))
	entries, m := Build(kev, kevAsOf, kevVer, epss, epssAsOf, nil, nil, nil, nil)

	dir := t.TempDir()
	path, err := Write(dir, entries, m)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if got.Version != m.Version || got.EntryCount != 3 {
		t.Errorf("manifest round-trip mismatch: %+v", got)
	}
}

func TestRefresh_OverHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/kev", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(kevFixture))
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, _ *http.Request) {
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(epssFixture))
		_ = gz.Close()
	})
	// ExploitDB fixture: references a CVE already in the KEV+EPSS union, so the entry count stays 3
	// while the public-exploit ref is merged onto Log4Shell.
	mux.HandleFunc("/exploitdb", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("file,id,description,codes,verified\nx.txt,12345,Log4Shell,CVE-2021-44228,1\n"))
	})
	// Metasploit fixture: an EXPLOIT module for the same CVE, so the entry count stays 3 while
	// Log4Shell gains the weaponized ref alongside the PoC one. An `auxiliary` module for a second
	// CVE is included and must NOT count — a scanner is not a weapon.
	mux.HandleFunc("/metasploit", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "a": {"fullname":"exploit/multi/http/log4shell_header_injection","type":"exploit","references":["CVE-2021-44228"]},
		  "b": {"fullname":"auxiliary/scanner/http/log4shell_scanner","type":"auxiliary","references":["CVE-2021-45046"]}
		}`))
	})
	// Nuclei template index: a template for the SAME CVE, so the entry count stays 3 while
	// Log4Shell gains a template path. A line with no file_path is included and must be
	// skipped — recording a CVE as testable with no template to name restores exactly the
	// bug the index exists to fix.
	mux.HandleFunc("/nuclei", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ID":"CVE-2021-44228","file_path":"http/cves/2021/CVE-2021-44228.yaml"}` + "\n" +
			`{"ID":"CVE-2021-45046","file_path":""}` + "\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	opts := RefreshOptions{
		OutDir:        dir,
		KEVURL:        srv.URL + "/kev",
		EPSSURL:       srv.URL + "/epss",
		ExploitDBURL:  srv.URL + "/exploitdb",
		MetasploitURL: srv.URL + "/metasploit",
		NucleiURL:     srv.URL + "/nuclei",
	}
	assertAllFeedsStubbed(t, opts, srv.URL)
	m, path, err := Refresh(context.Background(), opts)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if m.EntryCount != 3 {
		t.Errorf("refreshed corpus entry count = %d, want 3", m.EntryCount)
	}
	if m.ExploitCount != 1 {
		t.Errorf("refreshed corpus exploit_count = %d, want 1", m.ExploitCount)
	}
	if m.WeaponizedCount != 1 {
		t.Errorf("refreshed corpus weaponized_count = %d, want 1 (the auxiliary module must not count)", m.WeaponizedCount)
	}
	if m.TemplateCount != 1 {
		t.Errorf("refreshed corpus template_count = %d, want 1 (the empty file_path must not count)", m.TemplateCount)
	}
	if !strings.HasSuffix(path, DataFileName) {
		t.Errorf("unexpected data path %q", path)
	}
}

// assertAllFeedsStubbed fails when the hermetic refresh test has left any feed URL pointing
// at the real internet.
//
// THIS HAS NOW HAPPENED TWICE, identically. Adding a feed means defaulting its URL in
// withDefaults, and the moment that default lands, every test that does not override it
// starts fetching the live source. Both times the symptom was a wrong entry count — 2526
// and then 4327 against a fixture of 3 — which reads like a merge bug rather than a test
// making a network call, so the diagnosis costs more than the fix.
//
// Reflection rather than one more remembered field: the next feed is guarded for free, and
// the failure names itself.
func assertAllFeedsStubbed(t *testing.T, opts RefreshOptions, stubBase string) {
	t.Helper()
	full := opts.withDefaults()
	v := reflect.ValueOf(full)
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String || !strings.HasSuffix(f.Name, "URL") {
			continue
		}
		got := v.Field(i).String()
		if got == "" {
			continue // an opt-in feed that is off for this run
		}
		if !strings.HasPrefix(got, stubBase) {
			t.Fatalf("RefreshOptions.%s points at %q, not the test server — this test would fetch "+
				"the LIVE feed, and the symptom is a wrong entry count that reads like a merge bug. "+
				"Stub it on the fixture mux.", f.Name, got)
		}
	}
}
