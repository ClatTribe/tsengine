package hooks

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// writeOnDiskCorpus writes a refreshed-style OSINT corpus containing a CVE
// that is NOT in the embedded snapshot, so a successful lookup proves the
// on-disk corpus (not the embedded one) is in effect.
func writeOnDiskCorpus(t *testing.T) string {
	t.Helper()
	entries := map[string]threatintel.Entry{
		"CVE-2099-12345": {
			KEV:  &types.KEVStatus{Listed: true, DateAdded: time.Date(2099, 1, 2, 0, 0, 0, 0, time.UTC)},
			EPSS: &types.EPSSScore{Score: 0.5, Percentile: 0.9, AsOf: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
	}
	m := threatintel.Manifest{
		Version:    "test-osint-v1",
		EPSSAsOf:   time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		KEVAsOf:    time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		EntryCount: 1,
	}
	path, err := threatintel.Write(t.TempDir(), entries, m)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewThreatIntel_LoadsOnDiskCorpus(t *testing.T) {
	path := writeOnDiskCorpus(t)
	t.Setenv(ThreatIntelCorpusEnv, path)

	h := NewThreatIntel()
	if h.CorpusVersion() != "test-osint-v1" {
		t.Errorf("version should come from the on-disk manifest, got %q", h.CorpusVersion())
	}
	// Apply enriches a finding for the on-disk-only CVE.
	f, _, _ := h.Apply(types.Finding{ID: "f-1", RuleID: "trivy::CVE-2099-12345"})
	if f.ThreatIntel == nil || f.ThreatIntel.KEV == nil || !f.ThreatIntel.KEV.Listed {
		t.Fatalf("on-disk CVE should be enriched: %+v", f.ThreatIntel)
	}
}

func TestNewThreatIntel_FallsBackToEmbedded(t *testing.T) {
	t.Setenv(ThreatIntelCorpusEnv, "/no/such/corpus.json")

	h := NewThreatIntel() // must not panic; falls back to embedded
	if h.CorpusVersion() != ThreatIntelCorpusVersion {
		t.Errorf("bad on-disk path should fall back to embedded version, got %q", h.CorpusVersion())
	}
	// An embedded CVE still resolves.
	f, _, _ := h.Apply(types.Finding{ID: "f-1", RuleID: "trivy::CVE-2021-44228"})
	if f.ThreatIntel == nil {
		t.Error("embedded fallback should still enrich a known CVE")
	}
}

func TestThreatIntelCorpusInfo_ReflectsManifest(t *testing.T) {
	path := writeOnDiskCorpus(t)
	t.Setenv(ThreatIntelCorpusEnv, path)
	ver, _, epssAsOf := ThreatIntelCorpusInfo()
	if ver != "test-osint-v1" {
		t.Errorf("corpus info version = %q, want test-osint-v1", ver)
	}
	if epssAsOf.Year() != 2099 {
		t.Errorf("epss as-of = %v, want 2099", epssAsOf)
	}
}

// With TSENGINE_KEV_ESCALATE set, a sub-high finding whose CVE is on KEV is bumped to high + logs a promote.
func TestThreatIntel_KEVEscalateOptIn(t *testing.T) {
	path := writeOnDiskCorpus(t)
	t.Setenv(ThreatIntelCorpusEnv, path)
	t.Setenv(KEVEscalateEnv, "1")

	h := NewThreatIntel()
	f, audit, _ := h.Apply(types.Finding{ID: "f-1", RuleID: "trivy::CVE-2099-12345", Severity: types.SeverityMedium})
	if f.Severity != types.SeverityHigh {
		t.Errorf("a KEV-listed medium finding should escalate to high, got %s", f.Severity)
	}
	if len(audit) != 1 || audit[0].Rule != "threat_intel::kev-escalate" || audit[0].Action != "promote" {
		t.Errorf("escalation should log a kev-escalate promote, got %+v", audit)
	}
	// A finding already at/above high is left alone (never downgrade, never redundant-bump).
	hi, _, _ := h.Apply(types.Finding{ID: "f-2", RuleID: "trivy::CVE-2099-12345", Severity: types.SeverityCritical})
	if hi.Severity != types.SeverityCritical {
		t.Errorf("an already-critical finding must not change, got %s", hi.Severity)
	}
}

// Default (no env) keeps the annotation-only contract: a KEV-listed medium finding is annotated, NOT bumped.
func TestThreatIntel_KEVNoEscalateByDefault(t *testing.T) {
	path := writeOnDiskCorpus(t)
	t.Setenv(ThreatIntelCorpusEnv, path)
	// KEVEscalateEnv deliberately unset.

	h := NewThreatIntel()
	f, audit, _ := h.Apply(types.Finding{ID: "f-1", RuleID: "trivy::CVE-2099-12345", Severity: types.SeverityMedium})
	if f.Severity != types.SeverityMedium {
		t.Errorf("default behaviour is annotation-only — severity must stay medium, got %s", f.Severity)
	}
	if len(audit) != 1 || audit[0].Rule != "threat_intel::kev-listed" {
		t.Errorf("default should log the kev-listed annotation, got %+v", audit)
	}
}
