package grc

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestRealCrosswalk_FlowsToGRC closes the loop with REAL data: a real SQLi finding (CWE-89) through the
// actual compliance.map hook must produce control gaps — with REAL control ids — in the frameworks the
// crosswalk maps it to. This is the faithful "accurately implemented" check: crosswalk corpus → L1.5 hook
// → grc.Apply → Posture → Report, no synthetic mapping. (#527 made the crosswalk 43-CWE-deep; this proves
// a finding actually traverses it to an auditor-facing gap.)
func TestRealCrosswalk_FlowsToGRC(t *testing.T) {
	ctx := context.Background()
	h := hooks.NewCompliance()
	in := types.Finding{
		ID: "f-sqli", Title: "SQL injection", Severity: types.SeverityHigh,
		CWE: []string{"CWE-89"}, DiscoveredAt: time.Now().UTC(),
	}
	out, _, keep := h.Apply(in)
	if !keep || out.Compliance == nil {
		t.Fatal("compliance.map produced no annotation for CWE-89")
	}

	g := &GRC{Store: store.NewMemory()}
	if err := g.Store.PutFinding(ctx, "t1", out); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(ctx, "t1", out); err != nil {
		t.Fatal(err)
	}
	// CWE-89 (injection) maps to SOC2 + NIST 800-53 SI-10 in the crosswalk — both must show a real gap.
	for _, fw := range []string{FrameworkSOC2, FrameworkNIST80053} {
		r, err := g.Report(ctx, "t1", fw)
		if err != nil {
			t.Fatal(err)
		}
		if r.GapCount == 0 {
			t.Errorf("%s: a real CWE-89 finding produced no compliance gap end-to-end", fw)
		}
		for _, row := range r.Rows {
			if row.ControlID == "" {
				t.Errorf("%s: a gap row carries an empty control id", fw)
			}
		}
	}
}

// complianceCiting returns a Compliance annotation citing exactly one control on one framework.
// It is the inverse of frameworkControls — if a framework is added to pkg/types.Compliance + Frameworks
// but missed here, the all-frameworks test below fails loudly (the 4-mirror guard).
func complianceCiting(framework, ctrl string) *types.Compliance {
	c := &types.Compliance{}
	switch framework {
	case FrameworkSOC2:
		c.SOC2 = []string{ctrl}
	case FrameworkISO27001:
		c.ISO27001 = []string{ctrl}
	case FrameworkPCI:
		c.PCI = []string{ctrl}
	case FrameworkHIPAA:
		c.HIPAA = []string{ctrl}
	case FrameworkCISv8:
		c.CISv8 = []string{ctrl}
	case FrameworkNISTCSF:
		c.NISTCSF = []string{ctrl}
	case FrameworkGDPR:
		c.GDPR = []string{ctrl}
	case FrameworkISO27701:
		c.ISO27701 = []string{ctrl}
	case FrameworkNIST80053:
		c.NIST80053 = []string{ctrl}
	case FrameworkNIST800171:
		c.NIST800171 = []string{ctrl}
	case FrameworkCCPA:
		c.CCPA = []string{ctrl}
	case FrameworkSOX:
		c.SOX = []string{ctrl}
	case FrameworkFedRAMP:
		c.FedRAMP = []string{ctrl}
	case FrameworkDPDP:
		c.DPDP = []string{ctrl}
	case FrameworkCMMC:
		c.CMMC = []string{ctrl}
	case FrameworkISO42001:
		c.ISO42001 = []string{ctrl}
	case FrameworkNISTAIRMF:
		c.NISTAIRMF = []string{ctrl}
	case FrameworkISO27018:
		c.ISO27018 = []string{ctrl}
	case FrameworkISO22301:
		c.ISO22301 = []string{ctrl}
	case FrameworkPIPEDA:
		c.PIPEDA = []string{ctrl}
	case FrameworkGLBA:
		c.GLBA = []string{ctrl}
	case FrameworkEUAIAct:
		c.EUAIAct = []string{ctrl}
	default:
		return nil // an unhandled framework → the test below sees a nil and fails
	}
	return c
}

// TestEveryFramework_EndToEnd proves each of the 14 declared frameworks is ACCURATELY IMPLEMENTED through
// the full compliance chain — not merely declared. For each framework: a finding citing one of its controls
// must (1) Apply into a ControlGap, (2) surface in Posture, (3) resolve to its evidence finding in Report,
// and (4) render under a real display title (never the raw key). A framework that is declared in Frameworks
// but not wired through frameworkControls / the store filter / frameworkTitle fails here — which is exactly
// the "false compliant" failure mode (a framework that can never show a gap).
func TestEveryFramework_EndToEnd(t *testing.T) {
	const ctrl = "TEST-CTRL-1"
	for _, fw := range Frameworks {
		fw := fw
		t.Run(fw, func(t *testing.T) {
			g := &GRC{Store: store.NewMemory()}
			ctx := context.Background()
			comp := complianceCiting(fw, ctrl)
			if comp == nil {
				t.Fatalf("framework %q is declared in Frameworks but complianceCiting can't build an annotation for it — it is unwired", fw)
			}
			f := types.Finding{
				ID: "f-" + fw, Title: "sentinel finding for " + fw,
				Severity: types.SeverityHigh, Compliance: comp, DiscoveredAt: time.Now().UTC(),
			}
			if err := g.Store.PutFinding(ctx, "t1", f); err != nil {
				t.Fatal(err)
			}
			if err := g.Apply(ctx, "t1", f); err != nil {
				t.Fatal(err)
			}

			// (1)+(2) the control is now a gap in this framework's posture
			cs, err := g.Posture(ctx, "t1", fw)
			if err != nil {
				t.Fatal(err)
			}
			gap := false
			for _, c := range cs {
				if c.ControlID == ctrl && c.State == platform.ControlGap {
					gap = true
				}
			}
			if !gap {
				t.Fatalf("framework %q: control %q never surfaced as a gap (posture=%+v) — the framework is not wired end-to-end", fw, ctrl, cs)
			}

			// (3) the report resolves the gap to its citing finding
			r, err := g.Report(ctx, "t1", fw)
			if err != nil {
				t.Fatal(err)
			}
			if r.GapCount == 0 {
				t.Fatalf("framework %q: report shows no gaps despite a citing finding", fw)
			}
			resolved := false
			for _, row := range r.Rows {
				for _, ev := range row.Evidence {
					if ev.FindingID == f.ID && ev.Title == f.Title {
						resolved = true
					}
				}
			}
			if !resolved {
				t.Errorf("framework %q: report did not resolve the gap to its evidence finding %q", fw, f.ID)
			}

			// (4) a real display title, never the raw key (auditor-facing accuracy)
			if r.Title == "" || r.Title == fw {
				t.Errorf("framework %q: report Title %q is the raw key — no human display title (frameworkTitle gap)", fw, r.Title)
			}
		})
	}
}

// TestFrameworkMirrors_Consistent is the structural guard: a Compliance with EVERY field populated must
// expand (via frameworkControls) to exactly the declared Frameworks set — no declared framework unmapped,
// no mapped framework undeclared. Catches a mirror drift the moment a framework is half-added.
func TestFrameworkMirrors_Consistent(t *testing.T) {
	full := &types.Compliance{
		SOC2: []string{"x"}, ISO27001: []string{"x"}, PCI: []string{"x"}, HIPAA: []string{"x"},
		CISv8: []string{"x"}, NISTCSF: []string{"x"}, GDPR: []string{"x"}, ISO27701: []string{"x"},
		NIST80053: []string{"x"}, NIST800171: []string{"x"}, CCPA: []string{"x"}, SOX: []string{"x"},
		FedRAMP: []string{"x"}, DPDP: []string{"x"},
		CMMC: []string{"x"}, ISO42001: []string{"x"}, NISTAIRMF: []string{"x"},
		ISO27018: []string{"x"}, ISO22301: []string{"x"}, PIPEDA: []string{"x"}, GLBA: []string{"x"}, EUAIAct: []string{"x"},
	}
	got := frameworkControls(full)
	if len(got) != len(Frameworks) {
		t.Errorf("frameworkControls expanded %d frameworks, Frameworks declares %d — mirror drift", len(got), len(Frameworks))
	}
	for _, fw := range Frameworks {
		if _, ok := got[fw]; !ok {
			t.Errorf("framework %q is declared but frameworkControls does not map it", fw)
		}
		if FrameworkTitle(fw) == fw {
			t.Errorf("framework %q has no display title", fw)
		}
	}
}
