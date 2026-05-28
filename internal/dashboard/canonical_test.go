package dashboard

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func sampleScan() types.Scan {
	return types.Scan{
		ScanID: "scan-abc",
		Asset: types.Asset{
			Type:   types.AssetWebApplication,
			Target: "https://example.com",
		},
		StartedAt:   time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 5, 28, 10, 15, 0, 0, time.UTC),
		Engine: types.Engine{
			Version:            "tsengine 0.1.0",
			SandboxImageDigest: "sha256:deadbeef",
		},
		Corpus: types.Corpus{Nuclei: "v9.8.2"},
		FindingsRaw: []types.Finding{
			{
				ID: "f-002", RuleID: "r2", Tool: "nuclei",
				Severity: types.SeverityMedium, Title: "two",
				DiscoveredAt: time.Date(2026, 5, 28, 10, 5, 0, 0, time.UTC),
			},
			{
				ID: "f-001", RuleID: "r1", Tool: "sqlmap",
				Severity: types.SeverityHigh, Title: "one",
				DiscoveredAt: time.Date(2026, 5, 28, 10, 3, 0, 0, time.UTC),
			},
		},
		AnchorsFired: []string{"sqlmap_runner", "nuclei", "dalfox"},
	}
}

func TestCanonical_IsDeterministicAcrossSliceOrdering(t *testing.T) {
	a := sampleScan()

	b := sampleScan()
	// Swap findings + anchors order; Canonical should normalize both.
	b.FindingsRaw[0], b.FindingsRaw[1] = b.FindingsRaw[1], b.FindingsRaw[0]
	b.AnchorsFired = []string{"dalfox", "nuclei", "sqlmap_runner"}

	ca, err := Canonical(a)
	if err != nil {
		t.Fatalf("Canonical(a): %v", err)
	}
	cb, err := Canonical(b)
	if err != nil {
		t.Fatalf("Canonical(b): %v", err)
	}

	if !bytes.Equal(ca, cb) {
		t.Errorf("canonical output differs across slice ordering:\n a=%s\n b=%s", ca, cb)
	}
}

func TestCanonical_KeysSorted(t *testing.T) {
	scan := sampleScan()
	out, err := Canonical(scan)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	s := string(out)

	// Top-level keys: anchors_fired comes before asset comes before
	// completed_at, etc. (lexicographic). Spot-check one ordering:
	asset := strings.Index(s, `"asset"`)
	completedAt := strings.Index(s, `"completed_at"`)
	if asset < 0 || completedAt < 0 {
		t.Fatalf("expected asset and completed_at in output; got: %s", s)
	}
	if asset > completedAt {
		t.Errorf(`"asset" should appear before "completed_at" (lexicographic); got %s`, s)
	}
}

func TestCanonical_StripsAttestation(t *testing.T) {
	scan := sampleScan()
	scan.Attestation = &types.Attestation{
		SHA256:    "deadbeef",
		Signer:    "test",
		Signature: "abc",
	}
	out, err := Canonical(scan)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if strings.Contains(string(out), "attestation") {
		t.Errorf("Canonical should strip attestation block; got: %s", out)
	}
}

func TestCanonical_RejectsNilFindings(t *testing.T) {
	// Empty scan should still canonicalize cleanly.
	scan := types.Scan{
		ScanID:    "s",
		StartedAt: time.Now().UTC(),
	}
	if _, err := Canonical(scan); err != nil {
		t.Errorf("Canonical(empty scan): %v", err)
	}
}

func TestCanonical_NoInsignificantWhitespace(t *testing.T) {
	scan := sampleScan()
	out, err := Canonical(scan)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	// String values can contain spaces (e.g. "tsengine 0.1.0"), so we
	// check for the specific separator patterns the standard encoder
	// emits when not in compact mode: ", " (comma-space) and ": "
	// (colon-space), plus newlines and tabs.
	for _, pat := range []string{", ", ": ", "\n", "\t", "\r"} {
		if bytes.Contains(out, []byte(pat)) {
			t.Errorf("canonical output contains insignificant whitespace pattern %q: %s", pat, out)
		}
	}
}

func TestCanonical_RepeatedCallsByteIdentical(t *testing.T) {
	// Reproducibility invariant (CLAUDE.md §10): N calls on the same
	// input produce byte-identical output.
	scan := sampleScan()
	first, err := Canonical(scan)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := Canonical(scan)
		if err != nil {
			t.Fatalf("Canonical (iter %d): %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Errorf("Canonical not deterministic at iter %d", i)
		}
	}
}
