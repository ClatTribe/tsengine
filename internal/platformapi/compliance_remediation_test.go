package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestBuildRemediationPrompt_GroundsInControlsAndFindings(t *testing.T) {
	gaps := []grc.ReportRow{
		{ControlID: "CC6.1", Gap: true, Evidence: []grc.ReportEvidence{
			{FindingID: "f-1", Title: "SQL injection in search", Severity: types.SeverityHigh},
		}},
		{ControlID: "CC7.2", Gap: true, Evidence: []grc.ReportEvidence{
			{FindingID: "f-2", Title: "No centralized logging", Severity: types.SeverityMedium},
		}},
	}
	p := buildRemediationPrompt("SOC 2", gaps)
	for _, want := range []string{"SOC 2", "CC6.1", "SQL injection in search", "CC7.2", "No centralized logging", "Do NOT invent"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestComplianceRemediation_GatedWithoutGRCorLLM(t *testing.T) {
	// No GRC configured → 400 (never a fabricated plan).
	d := Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"}
	rec := do(NewHandler(d), "POST", "/v1/compliance/soc2/remediation", "t1", "{}")
	if rec.Code != 400 {
		t.Fatalf("without GRC the endpoint must gate (400), got %d: %s", rec.Code, rec.Body.String())
	}
}
