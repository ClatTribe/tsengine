// Package findingstore is a durable, lifecycle-aware findings database — the
// backbone of the retainer/continuous model (roadmap §4 / §7-#1). It deduplicates
// findings across scans by a stable fingerprint, tracks each through a lifecycle
// (open → fixed → verified → closed, with reopen), assigns SLA due dates by
// severity, and records an auditable event history. Single-file JSON backed (no
// external DB dependency); multi-tenant SQL is the separate platform layer.
package findingstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Status is the lifecycle state of a tracked finding.
type Status string

const (
	StatusOpen         Status = "open"          // currently observed, not remediated
	StatusFixed        Status = "fixed"         // no longer observed in the latest scan
	StatusVerified     Status = "verified"      // fix confirmed (re-tested clean)
	StatusClosed       Status = "closed"        // resolved + accepted (terminal)
	StatusReopened     Status = "reopened"      // reappeared after being fixed
	StatusAcceptedRisk Status = "accepted_risk" // knowingly not fixing (terminal-ish)
)

// slaBySeverity is the remediation window per severity.
var slaBySeverity = map[string]time.Duration{
	"critical": 7 * 24 * time.Hour,
	"high":     30 * 24 * time.Hour,
	"medium":   90 * 24 * time.Hour,
	"low":      180 * 24 * time.Hour,
	"info":     365 * 24 * time.Hour,
}

// Event is one lifecycle transition (audit trail).
type Event struct {
	At   time.Time `json:"at"`
	From Status    `json:"from,omitempty"`
	To   Status    `json:"to"`
	Note string    `json:"note,omitempty"`
}

// Record is a tracked finding, deduplicated across scans.
type Record struct {
	ID        string    `json:"id"` // stable fingerprint
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    Status    `json:"status"`
	Asset     string    `json:"asset"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	DueAt     time.Time `json:"due_at"`
	Seen      []string  `json:"seen_in,omitempty"` // scan/engagement ids that observed it
	History   []Event   `json:"history,omitempty"`
}

// Store is the findings database.
type Store struct {
	Records map[string]*Record `json:"records"`
}

// New returns an empty store.
func New() *Store { return &Store{Records: map[string]*Record{}} }

// fingerprint is the stable identity of a finding across scans: asset + rule +
// endpoint, normalized. Same logical issue → same record, even across runs.
func fingerprint(asset, rule, endpoint string) string {
	key := strings.ToLower(strings.TrimSpace(asset) + "|" + strings.TrimSpace(rule) + "|" + normEndpoint(endpoint))
	sum := sha256.Sum256([]byte(key))
	return "F-" + hex.EncodeToString(sum[:])[:12]
}

// normEndpoint strips a trailing query VALUE so /x?id=1 and /x?id=2 collapse.
func normEndpoint(e string) string {
	if i := strings.IndexByte(e, '?'); i >= 0 {
		base := e[:i]
		q := e[i+1:]
		if eq := strings.IndexByte(q, '='); eq >= 0 {
			return base + "?" + q[:eq+1]
		}
		return base + "?" + q
	}
	return e
}

// inbound is the normalized shape ingest works over (from any source).
type inbound struct {
	rule, title, severity, asset, endpoint, tool string
}

// IngestScan folds an L1 scan's enriched findings into the store, applying
// lifecycle transitions. scanID identifies the run. now is the clock.
// Returns (new, reopened, fixed) counts.
func (s *Store) IngestScan(scan types.Scan, now time.Time) (newN, reopenN, fixedN int) {
	asset := scan.Asset.Target
	findings := scan.FindingsEnriched
	if len(findings) == 0 {
		findings = scan.FindingsRaw
	}
	var in []inbound
	for _, f := range findings {
		title := f.Title
		if title == "" {
			title = f.RuleID
		}
		in = append(in, inbound{f.RuleID, title, string(f.Severity), asset, f.Endpoint, f.Tool})
	}
	return s.ingest(scan.ScanID, asset, in, now)
}

// IngestWebEvidence folds a web-agent evidence bundle into the store.
func (s *Store) IngestWebEvidence(b *webagent.EvidenceBundle, now time.Time) (newN, reopenN, fixedN int) {
	var in []inbound
	for _, ef := range b.Findings {
		sev := ef.Severity
		if sev == "" {
			sev = "high"
		}
		in = append(in, inbound{"webagent::" + ef.Class, humanClass(ef.Class), sev, b.Target, ef.Route, "webagent"})
	}
	return s.ingest(scanIDFromBundle(b), b.Target, in, now)
}

func (s *Store) ingest(scanID, asset string, in []inbound, now time.Time) (newN, reopenN, fixedN int) {
	present := map[string]bool{}
	for _, f := range in {
		id := fingerprint(f.asset, f.rule, f.endpoint)
		present[id] = true
		rec, ok := s.Records[id]
		if !ok {
			rec = &Record{
				ID: id, Title: f.title, Severity: strings.ToLower(f.severity), Status: StatusOpen,
				Asset: f.asset, Endpoint: f.endpoint, Tool: f.tool, FirstSeen: now, LastSeen: now,
				DueAt:   now.Add(sla(f.severity)),
				History: []Event{{At: now, To: StatusOpen, Note: "first observed in " + scanID}},
			}
			rec.addSeen(scanID)
			s.Records[id] = rec
			newN++
			continue
		}
		rec.LastSeen = now
		rec.addSeen(scanID)
		// reappeared after being fixed/verified → reopen
		if rec.Status == StatusFixed || rec.Status == StatusVerified {
			rec.transition(StatusReopened, now, "reappeared in "+scanID)
			rec.DueAt = now.Add(sla(rec.Severity))
			reopenN++
		}
	}
	// anything previously open/reopened but NOT in this scan of the same asset → fixed
	for id, rec := range s.Records {
		if present[id] || rec.Asset != asset {
			continue
		}
		if rec.Status == StatusOpen || rec.Status == StatusReopened {
			rec.transition(StatusFixed, now, "no longer observed in "+scanID)
			fixedN++
		}
	}
	return newN, reopenN, fixedN
}

// Transition manually moves a finding to a new status (e.g. an analyst verifying a
// fix, accepting risk, or closing). Returns false if the id is unknown.
func (s *Store) Transition(id string, to Status, note string, now time.Time) bool {
	rec, ok := s.Records[id]
	if !ok {
		return false
	}
	rec.transition(to, now, note)
	return true
}

// Assign sets the owner of a finding.
func (s *Store) Assign(id, owner string) bool {
	rec, ok := s.Records[id]
	if !ok {
		return false
	}
	rec.Owner = owner
	return true
}

func (r *Record) transition(to Status, now time.Time, note string) {
	if r.Status == to {
		return
	}
	r.History = append(r.History, Event{At: now, From: r.Status, To: to, Note: note})
	r.Status = to
}

func (r *Record) addSeen(scanID string) {
	if scanID == "" {
		return
	}
	for _, s := range r.Seen {
		if s == scanID {
			return
		}
	}
	r.Seen = append(r.Seen, scanID)
}

// Filter selects records.
type Filter struct {
	Status   Status // empty = any
	Severity string // empty = any
	Asset    string // empty = any
	Owner    string // empty = any
	OpenOnly bool   // open + reopened
}

func (f Filter) match(r *Record) bool {
	if f.Status != "" && r.Status != f.Status {
		return false
	}
	if f.OpenOnly && r.Status != StatusOpen && r.Status != StatusReopened {
		return false
	}
	if f.Severity != "" && r.Severity != strings.ToLower(f.Severity) {
		return false
	}
	if f.Asset != "" && r.Asset != f.Asset {
		return false
	}
	if f.Owner != "" && r.Owner != f.Owner {
		return false
	}
	return true
}

// List returns matching records, severity-sorted then by first-seen.
func (s *Store) List(f Filter) []*Record {
	var out []*Record
	for _, r := range s.Records {
		if f.match(r) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRank(out[i].Severity), sevRank(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

// Overdue returns open/reopened records past their SLA due date.
func (s *Store) Overdue(now time.Time) []*Record {
	var out []*Record
	for _, r := range s.List(Filter{OpenOnly: true}) {
		if now.After(r.DueAt) {
			out = append(out, r)
		}
	}
	return out
}

// Counts returns record counts per status.
func (s *Store) Counts() map[Status]int {
	c := map[Status]int{}
	for _, r := range s.Records {
		c[r.Status]++
	}
	return c
}

// Save writes the store to path (atomic-ish: temp then rename).
func (s *Store) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a store from path; returns an empty store if the file is absent.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, err
	}
	s := New()
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.Records == nil {
		s.Records = map[string]*Record{}
	}
	return s, nil
}

// --- helpers ---

func sla(sev string) time.Duration {
	if d, ok := slaBySeverity[strings.ToLower(sev)]; ok {
		return d
	}
	return 90 * 24 * time.Hour
}

var sevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func sevRank(s string) int {
	if r, ok := sevOrder[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}

var humanClassMap = map[string]string{
	"sqli": "SQL Injection", "xss": "Cross-Site Scripting (XSS)", "open_redirect": "Open Redirect",
	"path_traversal": "Path Traversal / LFI", "command_injection": "OS Command Injection",
}

func humanClass(c string) string {
	if h, ok := humanClassMap[strings.ToLower(c)]; ok {
		return h
	}
	return c
}

func scanIDFromBundle(b *webagent.EvidenceBundle) string {
	if b.Attestation != nil && b.Attestation.SHA256 != "" {
		return "web-" + b.Attestation.SHA256[:min(8, len(b.Attestation.SHA256))]
	}
	return "web-engagement"
}
