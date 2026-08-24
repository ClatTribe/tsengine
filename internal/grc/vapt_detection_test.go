package grc

import (
	"strings"
	"testing"
	"time"
)

// vapt_detection_test.go covers the half the report was missing: it stated how old the THREAT INTEL
// was and said nothing about how old the DETECTION SIGNATURES were. The first governs how confident
// we are about priority; the second governs what could be found at all, and only the second sets the
// finding count.

func TestDetectionProvenance_StatesWhatTestedTheScope(t *testing.T) {
	p := &DetectionProvenance{
		Digest:  "sha256:ab12cd34ef567890abcdef1234567890abcdef1234567890abcdef1234567890",
		BuiltAt: time.Now().AddDate(0, 0, -3).UTC(),
		AgeDays: 3,
	}
	line := RenderDetectionProvenance(p)
	if !strings.Contains(line, "sha256:ab12cd34ef") {
		t.Errorf("the image identity is missing from the provenance line: %q", line)
	}
	if !strings.Contains(line, "move only when this image is rebuilt") {
		t.Error("the line must say that baked signatures do not refresh at runtime — that is the fact a " +
			"reader needs in order to interpret the finding count")
	}
	if c := p.DetectionCaveat(); c != "" {
		t.Errorf("a 3-day-old image is current; no caveat expected, got %q", c)
	}
}

func TestDetectionProvenance_OldImageCarriesTheCaveat(t *testing.T) {
	p := &DetectionProvenance{Digest: "sha256:deadbeef", AgeDays: 120}
	c := p.DetectionCaveat()
	if c == "" {
		t.Fatal("a 120-day-old signature set produced no caveat — a low finding count would then read " +
			"as an all-clear about the customer rather than partly about us")
	}
	for _, want := range []string{"not current", "120 days", "no runtime refresh", "not only about this scope"} {
		if !strings.Contains(c, want) {
			t.Errorf("caveat is missing %q:\n%s", want, c)
		}
	}
}

func TestDetectionProvenance_ATagIsNotABuild(t *testing.T) {
	// The realistic default: the deployment runs a mutable tag and nothing recorded a digest or a
	// build date. The report cannot say what tested the customer, and MUST say that rather than
	// printing a reference that looks like an identity.
	p := &DetectionProvenance{ImageRef: "tsengine/sandbox:latest"}
	line := RenderDetectionProvenance(p)
	if !strings.Contains(line, "mutable tag") {
		t.Errorf("a tag-only reference must be called out as not identifying a build: %q", line)
	}
	if !strings.Contains(line, "cannot state which signature versions") {
		t.Error("the line must admit the question is unanswerable here. Silence would read as a clean answer.")
	}
}

func TestDetectionProvenance_NilIsSilentNotWrong(t *testing.T) {
	// Back-compat: a caller that does not populate this (every caller, before now) must not start
	// rendering an empty or misleading line.
	if got := RenderDetectionProvenance(nil); got != "" {
		t.Errorf("nil provenance rendered %q, want empty", got)
	}
	var p *DetectionProvenance
	if got := p.DetectionCaveat(); got != "" {
		t.Errorf("nil provenance produced caveat %q, want empty", got)
	}
}

func TestVAPTMarkdown_CarriesBothProvenanceHalves(t *testing.T) {
	r := &VAPTReport{
		Findings:  []VAPTFinding{{ID: "f1", Title: "x", Severity: "high", Tool: "nuclei"}},
		Intel:     &IntelProvenance{Version: "ti-2026-05-01", AgeDays: 115, Embedded: true, Stale: true},
		Detection: &DetectionProvenance{Digest: "sha256:abc123def456", AgeDays: 90, Stale: true},
	}
	md := RenderVAPTMarkdown(r)
	if !strings.Contains(md, "exploitation intelligence behind this report is not current") {
		t.Error("the intel caveat regressed")
	}
	if !strings.Contains(md, "detection signatures behind this report are not current") {
		t.Error("the detection caveat is absent — the report still says how old the intel is and " +
			"nothing about how old the signatures are, which is the asymmetry this closes")
	}
	if !strings.Contains(md, "Detection corpus:") {
		t.Error("the detection provenance line is absent from the methodology section")
	}
}
