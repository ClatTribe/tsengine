package threatintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
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
	entries, m := Build(kev, kevAsOf, kevVer, epss, epssAsOf, nil, nil)

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
	entries, m := Build(kev, kevAsOf, kevVer, epss, epssAsOf, nil, nil)

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
	// Metasploit fixture: a framework-weaponized module for the SAME Log4Shell CVE, so the entry count
	// stays 3 and exploit_count stays 1 while a metasploit: ref is unioned onto the ExploitDB overlay.
	mux.HandleFunc("/metasploit", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"exploit/multi/http/log4shell":{"fullname":"exploit/multi/http/log4shell","type":"exploit","references":["CVE-2021-44228"]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	m, path, err := Refresh(context.Background(), RefreshOptions{
		OutDir:        dir,
		KEVURL:        srv.URL + "/kev",
		EPSSURL:       srv.URL + "/epss",
		ExploitDBURL:  srv.URL + "/exploitdb",
		MetasploitURL: srv.URL + "/metasploit",
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if m.EntryCount != 3 {
		t.Errorf("refreshed corpus entry count = %d, want 3", m.EntryCount)
	}
	if m.ExploitCount != 1 {
		t.Errorf("refreshed corpus exploit_count = %d, want 1", m.ExploitCount)
	}
	// both weaponization overlays must be recorded in the pinned manifest's provenance.
	var hasEDB, hasMSF bool
	for _, s := range m.Sources {
		if s == ExploitDBURL {
			hasEDB = true
		}
		if s == MetasploitURL {
			hasMSF = true
		}
	}
	if !hasEDB || !hasMSF {
		t.Errorf("manifest sources must list both exploit overlays, got %v", m.Sources)
	}
	if !strings.HasSuffix(path, DataFileName) {
		t.Errorf("unexpected data path %q", path)
	}
}
