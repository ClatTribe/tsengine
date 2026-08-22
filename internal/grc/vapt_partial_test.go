package grc

import (
	"strings"
	"testing"
	"time"
)

// "No open vulnerabilities — every monitored asset is currently clean" is the most quotable sentence
// in a document customers hand to prospects and auditors. A scan that lost its tools has not earned it.
//
// The report already refused to say it about an estate nothing had scanned (Untested). It could not
// see the case one step in: every target scanned, tools dead, zero findings — which produces exactly
// the same empty finding list for a completely different reason.
func TestRenderVAPT_DoesNotCallAPartiallyScannedEstateClean(t *testing.T) {
	r := &VAPTReport{
		TenantName: "Acme", GeneratedAt: time.Now().UTC(),
		Scope:             []string{"https://app.acme.test"},
		PartiallyAssessed: []string{"https://app.acme.test"},
	}
	md := RenderVAPTMarkdown(r)

	if strings.Contains(md, "every monitored asset is currently clean") {
		t.Fatal("the report called an estate clean when its only target's last scan lost tools — " +
			"clean is a claim about what was looked for")
	}
	if !strings.Contains(md, "PARTIALLY assessed") {
		t.Errorf("the summary must say what is wrong with the result, got:\n%s", md)
	}
	if !strings.Contains(md, "**partially assessed**") {
		t.Errorf("the scope list must mark the target inline — a reader should not have to " +
			"cross-reference the summary to learn a target was half-scanned")
	}
}

// The control: a genuinely complete, genuinely clean estate must STILL read clean. A report that
// hedges everything is one nobody can use, and the hedge would then be worthless where it matters.
func TestRenderVAPT_ACompletelyScannedCleanEstateStillReadsClean(t *testing.T) {
	r := &VAPTReport{
		TenantName: "Acme", GeneratedAt: time.Now().UTC(),
		Scope: []string{"https://app.acme.test"},
	}
	if md := RenderVAPTMarkdown(r); !strings.Contains(md, "every monitored asset is currently clean") {
		t.Errorf("every target scanned, every tool ran, nothing found — that IS clean:\n%s", md)
	}
}

// Never-scanned outranks partially-scanned for the same target: "not assessed" is the stronger and
// more accurate statement, and showing both would be two labels for one target.
func TestRenderVAPT_UntestedOutranksPartial(t *testing.T) {
	r := &VAPTReport{
		TenantName: "Acme", GeneratedAt: time.Now().UTC(),
		Scope:             []string{"https://app.acme.test"},
		Untested:          []string{"https://app.acme.test"},
		PartiallyAssessed: []string{"https://app.acme.test"},
	}
	md := RenderVAPTMarkdown(r)
	if strings.Contains(md, "**partially assessed**") {
		t.Error("a target nothing has scanned is NOT assessed, not partially assessed")
	}
	if !strings.Contains(md, "**not assessed**") {
		t.Error("want the stronger statement")
	}
}
