package findingstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func scanWith(id, target string, fs ...types.Finding) types.Scan {
	return types.Scan{ScanID: id, Asset: types.Asset{Type: "web_application", Target: target}, FindingsEnriched: fs}
}

func f(id, rule, sev, endpoint string) types.Finding {
	return types.Finding{ID: id, RuleID: rule, Severity: types.Severity(sev), Title: rule, Endpoint: endpoint, Tool: "nuclei"}
}

// TestLifecycle walks a finding open → fixed → reopened across three scans, the
// core retainer value.
func TestLifecycle(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New()

	// scan 1: two findings appear
	n, r, fx := s.IngestScan(scanWith("s1", "https://app",
		f("a", "nuclei::sqli", "high", "https://app/search?q="),
		f("b", "nuclei::xss", "medium", "https://app/echo?name="),
	), t0)
	if n != 2 || r != 0 || fx != 0 {
		t.Fatalf("scan1 = new %d reopen %d fixed %d, want 2/0/0", n, r, fx)
	}
	if len(s.List(Filter{OpenOnly: true})) != 2 {
		t.Fatalf("want 2 open after scan1")
	}

	// scan 2 (a week later): sqli fixed (gone), xss persists
	t1 := t0.Add(7 * 24 * time.Hour)
	n, _, fx = s.IngestScan(scanWith("s2", "https://app",
		f("b", "nuclei::xss", "medium", "https://app/echo?name="),
	), t1)
	if n != 0 || fx != 1 {
		t.Fatalf("scan2 = new %d fixed %d, want 0 new / 1 fixed", n, fx)
	}
	// the sqli record is now fixed
	sqli := s.findByRule("nuclei::sqli")
	if sqli == nil || sqli.Status != StatusFixed {
		t.Fatalf("sqli not fixed: %+v", sqli)
	}

	// scan 3: sqli REAPPEARS → reopened
	t2 := t1.Add(7 * 24 * time.Hour)
	_, r, _ = s.IngestScan(scanWith("s3", "https://app",
		f("a", "nuclei::sqli", "high", "https://app/search?q="),
		f("b", "nuclei::xss", "medium", "https://app/echo?name="),
	), t2)
	if r != 1 {
		t.Fatalf("scan3 = reopen %d, want 1", r)
	}
	sqli = s.findByRule("nuclei::sqli")
	if sqli.Status != StatusReopened {
		t.Fatalf("sqli not reopened: %s", sqli.Status)
	}
	// it should carry its full history: open → fixed → reopened
	if len(sqli.History) != 3 {
		t.Errorf("sqli history = %d events, want 3: %+v", len(sqli.History), sqli.History)
	}
	// dedup: still one record per logical finding
	if len(s.Records) != 2 {
		t.Errorf("dedup failed: %d records, want 2", len(s.Records))
	}
}

// TestDedupAcrossParamValues: same endpoint with different query VALUES is one
// finding (the engine already shape-dedups; the store agrees).
func TestDedupAcrossParamValues(t *testing.T) {
	now := time.Now().UTC()
	s := New()
	s.IngestScan(scanWith("s1", "https://app", f("a", "nuclei::sqli", "high", "https://app/item?id=1")), now)
	s.IngestScan(scanWith("s2", "https://app", f("b", "nuclei::sqli", "high", "https://app/item?id=999")), now)
	if len(s.Records) != 1 {
		t.Fatalf("param values not deduped: %d records", len(s.Records))
	}
}

// TestOverdueSLA: a high finding is overdue after 30 days.
func TestOverdueSLA(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New()
	s.IngestScan(scanWith("s1", "https://app", f("a", "nuclei::sqli", "high", "https://app/x?q=")), t0)
	if len(s.Overdue(t0.Add(10*24*time.Hour))) != 0 {
		t.Error("high finding overdue too early (SLA is 30d)")
	}
	od := s.Overdue(t0.Add(31 * 24 * time.Hour))
	if len(od) != 1 {
		t.Fatalf("high finding not overdue after 31d: %d", len(od))
	}
}

// TestManualTransitionsAndPersistence: verify→close, assign, save+load round-trip.
func TestManualTransitionsAndPersistence(t *testing.T) {
	now := time.Now().UTC()
	s := New()
	s.IngestScan(scanWith("s1", "https://app", f("a", "nuclei::sqli", "high", "https://app/x?q=")), now)
	id := s.findByRule("nuclei::sqli").ID

	if !s.Transition(id, StatusVerified, "fix re-tested clean", now) {
		t.Fatal("transition failed")
	}
	if !s.Assign(id, "alice") {
		t.Fatal("assign failed")
	}
	if s.Transition("F-nonexistent", StatusClosed, "", now) {
		t.Error("transition on unknown id should fail")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rec := loaded.Records[id]
	if rec == nil || rec.Status != StatusVerified || rec.Owner != "alice" {
		t.Fatalf("round-trip lost state: %+v", rec)
	}
	// Load of a missing file returns an empty store, not an error
	empty, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil || len(empty.Records) != 0 {
		t.Errorf("missing-file load = %v, %d records", err, len(empty.Records))
	}
}

func TestIngestWebEvidence(t *testing.T) {
	now := time.Now().UTC()
	s := New()
	b := &webagent.EvidenceBundle{
		Target: "http://x", Attestation: &webagent.EvidenceAttest{SHA256: "deadbeefcafe"},
		Findings: []webagent.EvidenceFinding{
			{Finding: webagent.Finding{ID: "web-001", Route: "http://x/p?id=", Class: "sqli", Severity: "high"}},
		},
	}
	n, _, _ := s.IngestWebEvidence(b, now)
	if n != 1 {
		t.Fatalf("web evidence ingest = %d new, want 1", n)
	}
	if got := s.List(Filter{})[0].Title; got != "SQL Injection" {
		t.Errorf("title = %q, want SQL Injection", got)
	}
}

// findByRule locates a record by the rule id the fixtures stored as the title.
func (s *Store) findByRule(rule string) *Record {
	for _, r := range s.Records {
		if r.Title == rule {
			return r
		}
	}
	return nil
}
