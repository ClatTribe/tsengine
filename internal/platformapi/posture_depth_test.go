package platformapi

import (
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// posture_depth_test.go guards the SEAM, which is where the flag was lost.
//
// grc.Coverage grew ShallowCrosswalk/DepthNote and frameworkPosture — the DTO GET /v1/posture returns
// to the dashboard, the compliance page and reports — did not. So the caveat survived only as prose
// inside Readiness: a consumer could print it and could not badge, sort or filter on it, and a
// redesign that reworded the status line would drop it without noticing.
//
// Verified live before this fix: gdpr came back assessable=2 with the note in Readiness and no flag.

func TestPostureSummary_CarriesCrosswalkDepth(t *testing.T) {
	st := store.NewMemory()
	d := Deps{
		Store: st, Token: "platform-tok",
		GRC: &grc.GRC{Store: st, ControlUniverse: hooks.NewCompliance().ControlsFor},
	}
	ctx := t.Context()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	// A finding that maps into a SHALLOW framework (gdpr maps 2 controls) and a deep one
	// (nist_800_53 maps 20), so both sides of the assertion come from the real crosswalk.
	f := types.Finding{
		ID: "f1", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh,
		CWE: []string{"CWE-89"}, Endpoint: "app/db.go:12",
	}
	comp, ok := hooks.NewCompliance().Lookup(f.CWE)
	if !ok || comp == nil {
		t.Fatal("the real crosswalk produced no mapping for CWE-89. The fixture must exercise the real " +
			"crosswalk — a synthetic annotation here would test the DTO against a shape no finding has.")
	}
	f.Compliance = comp
	if err := st.PutFinding(ctx, "t1", f); err != nil {
		t.Fatal(err)
	}
	if err := d.GRC.Apply(ctx, "t1", f); err != nil {
		t.Fatal(err)
	}

	rec := do(NewHandler(d), "GET", "/v1/posture", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("posture: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Frameworks []frameworkPosture `json:"frameworks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Frameworks) == 0 {
		t.Fatal("no frameworks assessed — the fixture did not exercise the crosswalk, so this test " +
			"would pass while checking nothing")
	}

	var sawShallow, sawDeep bool
	for _, fw := range body.Frameworks {
		switch {
		case fw.Assessable > 0 && fw.Assessable < grc.ShallowCrosswalkBelow:
			sawShallow = true
			if !fw.ShallowCrosswalk {
				t.Errorf("%s has %d assessable control(s) and the API does not flag it shallow. The "+
					"coverage percentage's denominator is our own mapping, and a consumer cannot tell.",
					fw.Framework, fw.Assessable)
			}
			if fw.DepthNote == "" {
				t.Errorf("%s is flagged shallow with no depth note — the flag alone tells a UI to warn "+
					"and not what to say", fw.Framework)
			}
		case fw.Assessable >= grc.ShallowCrosswalkBelow:
			sawDeep = true
			if fw.ShallowCrosswalk || fw.DepthNote != "" {
				t.Errorf("%s maps %d controls and is hedged as shallow — the qualifier becomes noise if "+
					"it appears everywhere", fw.Framework, fw.Assessable)
			}
		}
	}
	if !sawShallow {
		t.Error("no shallow framework appeared, so the positive case was never exercised. gdpr, dpdp, " +
			"sox and pipeda all map fewer than four controls; if that changed, the depth floors in " +
			"grc should have failed first.")
	}
	if !sawDeep {
		t.Error("no deeply-mapped framework appeared, so the negative case was never exercised")
	}
}
