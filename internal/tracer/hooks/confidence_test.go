package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestConfidence_DefaultsToPatternMatch(t *testing.T) {
	h := NewConfidence()
	out, _ := h.Finalize([]types.Finding{
		{ID: "f-1", Tool: "semgrep"},
	})
	f := out[0]
	if f.VerificationStatus != types.VerificationPatternMatch {
		t.Errorf("uncorroborated finding should be pattern_match, got %q", f.VerificationStatus)
	}
	// semgrep base 0.60, no corroboration.
	if f.Confidence != 0.60 {
		t.Errorf("confidence = %v, want 0.60 (semgrep base)", f.Confidence)
	}
}

func TestConfidence_CorroborationUpgradesStatusAndScore(t *testing.T) {
	h := NewConfidence()
	out, _ := h.Finalize([]types.Finding{
		{ID: "f-1", Tool: "nuclei", CorroboratedBy: []string{"dalfox::xss"}},
	})
	f := out[0]
	if f.VerificationStatus != types.VerificationCorroborated {
		t.Errorf("an agreed finding should be corroborated, got %q", f.VerificationStatus)
	}
	// nuclei base 0.85 + 0.1 per corroborating source.
	if f.Confidence != 0.95 {
		t.Errorf("confidence = %v, want 0.95 (0.85 + 0.10)", f.Confidence)
	}
}

func TestConfidence_UnknownToolDefaultBaseAndClamp(t *testing.T) {
	h := NewConfidence()
	out, _ := h.Finalize([]types.Finding{
		// unknown tool (0.50) + 5 corroborators (0.50) would be 1.00 → clamped.
		{ID: "f-1", Tool: "mystery", CorroboratedBy: []string{"a", "b", "c", "d", "e"}},
	})
	if c := out[0].Confidence; c > 0.99 {
		t.Errorf("confidence must clamp to ≤0.99, got %v", c)
	}
}

func TestConfidence_DoesNotDowngradeVerified(t *testing.T) {
	h := NewConfidence()
	out, _ := h.Finalize([]types.Finding{
		{ID: "f-1", Tool: "sqlmap", VerificationStatus: types.VerificationVerified},
	})
	if out[0].VerificationStatus != types.VerificationVerified {
		t.Error("an already-verified finding must not be downgraded")
	}
	if out[0].Confidence < 0.95 {
		t.Errorf("verified finding confidence should be ≥0.95, got %v", out[0].Confidence)
	}
}
