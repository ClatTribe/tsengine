package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestBuildAdvisorPrompt_GroundsInCoverageAndManualAreas(t *testing.T) {
	rep := &grc.Report{
		Title:    "SOC 2",
		Coverage: grc.Coverage{AssessedControls: 3, AssessableControls: 10, AutomatedCoveragePct: 30, Gaps: 2, NotAssessed: 7},
		Rows:     []grc.ReportRow{{ControlID: "CC6.1", Gap: true}, {ControlID: "CC7.2", Gap: true}},
	}
	readiness := grc.ScopeReadiness([]string{"soc2"}, map[string]bool{"identity": true})
	p := buildAdvisorPrompt(rep, readiness)
	for _, want := range []string{"3 of 10", "CC6.1", `never call them "compliant"`, "auditor attestation", "Endpoint"} {
		if !strings.Contains(p, want) {
			t.Errorf("advisor prompt missing %q:\n%s", want, p)
		}
	}
}

// The advisor is gated on an LLM (with GRC configured + a real framework) → 400 without one, never a
// falsely-confident roadmap.
func TestAdvisor_GatedNoLLM(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), GRC: &grc.GRC{Store: st}, Token: "platform-tok"}
	rec := do(NewHandler(d), "POST", "/v1/compliance/soc2/advisor", "t1", "{}")
	if rec.Code != 400 {
		t.Fatalf("no LLM → 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
