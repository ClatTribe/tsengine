package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAssetType_AllValid(t *testing.T) {
	for _, a := range AllAssetTypes() {
		if !a.Valid() {
			t.Errorf("AssetType %q reported invalid by Valid()", a)
		}
	}
	if AssetType("not_a_type").Valid() {
		t.Errorf("unknown AssetType reported valid")
	}
}

func TestAssetType_AllTypes(t *testing.T) {
	// CLAUDE.md §3 promises exactly 8 asset types. Pin it.
	const want = 8
	if got := len(AllAssetTypes()); got != want {
		t.Errorf("AllAssetTypes(): got %d, want %d (CLAUDE.md §3)", got, want)
	}
}

func TestSeverity_Rank(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Error("critical should rank above high")
	}
	if SeverityHigh.Rank() <= SeverityMedium.Rank() {
		t.Error("high should rank above medium")
	}
	if SeverityInfo.Rank() <= 0 {
		t.Error("info should rank above 0")
	}
	if Severity("nonsense").Rank() != 0 {
		t.Error("unknown severity should rank 0")
	}
}

func TestScan_JSONRoundTrip(t *testing.T) {
	original := Scan{
		ScanID: "scan-abc",
		Asset: Asset{
			Type:   AssetWebApplication,
			Target: "https://example.com",
			Scope:  Scope{ScopeHosts: []string{"example.com"}},
		},
		StartedAt:   time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 5, 28, 10, 15, 0, 0, time.UTC),
		Engine: Engine{
			Version:            "tsengine 0.1.0",
			SandboxImageDigest: "sha256:deadbeef",
		},
		Corpus: Corpus{
			Nuclei:           "v9.8.2",
			ComplianceCorpus: "soc2-1.4.0+pci-4.0.0",
		},
		AnchorsFired: []string{"nuclei", "sqlmap_runner"},
		FindingsRaw: []Finding{{
			ID:           "f-001",
			RuleID:       "nuclei::sqli",
			Tool:         "nuclei",
			Severity:     SeverityHigh,
			CWE:          []string{"CWE-89"},
			Endpoint:     "https://example.com/search",
			Title:        "SQL injection",
			DiscoveredAt: time.Date(2026, 5, 28, 10, 3, 12, 0, time.UTC),
		}},
		FindingsEnriched: []Finding{{
			ID:       "f-001",
			RuleID:   "nuclei::sqli",
			Tool:     "nuclei",
			Severity: SeverityHigh,
			ThreatIntel: &ThreatIntel{
				CVSS: 9.8,
				KEV:  &KEVStatus{Listed: true, DateAdded: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			Compliance: &Compliance{
				SOC2: []string{"CC6.1"},
				PCI:  []string{"6.2.1"},
			},
			DiscoveredAt: time.Date(2026, 5, 28, 10, 3, 12, 0, time.UTC),
		}},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Scan
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ScanID != original.ScanID {
		t.Errorf("ScanID: got %q, want %q", decoded.ScanID, original.ScanID)
	}
	if decoded.Asset.Type != AssetWebApplication {
		t.Errorf("AssetType lost in roundtrip: got %q", decoded.Asset.Type)
	}
	if len(decoded.FindingsRaw) != 1 || decoded.FindingsRaw[0].ID != "f-001" {
		t.Errorf("FindingsRaw lost in roundtrip: %+v", decoded.FindingsRaw)
	}
	if decoded.FindingsEnriched[0].ThreatIntel == nil {
		t.Fatal("ThreatIntel lost in roundtrip")
	}
	if !decoded.FindingsEnriched[0].ThreatIntel.KEV.Listed {
		t.Error("KEV.Listed lost in roundtrip")
	}
	if decoded.FindingsEnriched[0].Compliance == nil ||
		len(decoded.FindingsEnriched[0].Compliance.SOC2) != 1 {
		t.Error("Compliance.SOC2 lost in roundtrip")
	}
}

func TestFinding_OmitemptySemantics(t *testing.T) {
	// A pre-L1.5 finding (FindingsRaw) should not carry empty enrichment
	// blocks in its JSON form — those fields are reserved for the
	// FindingsEnriched view.
	f := Finding{
		ID:           "f-001",
		RuleID:       "x",
		Tool:         "y",
		Severity:     SeverityHigh,
		Title:        "t",
		DiscoveredAt: time.Now(),
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(encoded)
	for _, banned := range []string{"surface_priority", "exploitability", "threat_intel", "compliance", "corroborated_by"} {
		if contains(s, banned) {
			t.Errorf("raw finding JSON contains enrichment field %q: %s", banned, s)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
