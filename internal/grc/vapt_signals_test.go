package grc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The engine computes ransomware linkage, Metasploit weaponization rank, and CISA's own
// BOD 22-01 deadline (CLAUDE.md §7); the VAPT deliverable was dropping all three. This locks
// them into the report — the finding page already shows them (#1310/#1311), the report must too.
func TestVAPTReport_SurfacesWeaponRankRansomwareAndDeadline(t *testing.T) {
	due := time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC)
	f := []types.Finding{{
		ID: "f-1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical,
		Title: "Log4Shell RCE", CWE: []string{"CWE-94"}, VerificationStatus: "corroborated",
		ThreatIntel: &types.ThreatIntel{
			CVSS: 10.0, WeaponRank: "excellent",
			KEV:  &types.KEVStatus{Listed: true, Ransomware: true, DueDate: due},
			EPSS: &types.EPSSScore{Score: 0.975},
		},
	}}
	r := ReportFromFindings(f, []string{"pkg:maven/log4j-core@2.14.1"}, "Acme", time.Now().UTC(), nil)

	if r.Summary.Ransomware != 1 {
		t.Fatalf("summary ransomware = %d, want 1", r.Summary.Ransomware)
	}
	vf := r.Findings[0]
	if !vf.Ransomware || vf.WeaponRank != "excellent" || vf.KEVDueDate != due {
		t.Fatalf("finding signals not carried: ransomware=%v rank=%q due=%v", vf.Ransomware, vf.WeaponRank, vf.KEVDueDate)
	}

	md := RenderVAPTMarkdown(r)
	for _, want := range []string{
		"ransomware-linked",
		"weaponized: excellent (Metasploit)",
		"CISA remediation deadline (BOD 22-01):** 2021-12-24",
		"**1 ransomware-linked**",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("full report missing %q", want)
		}
	}
	if !strings.Contains(RenderVAPTExecMarkdown(r), "**1 ransomware-linked**") {
		t.Error("exec summary missing ransomware line")
	}
}

// A finding with no ransomware/weaponization must not print those signals or an alarming "0
// ransomware-linked" line — conditional rendering, grounded (§10).
func TestVAPTReport_NoSignalsWhenAbsent(t *testing.T) {
	f := []types.Finding{{
		ID: "f-1", RuleID: "nuclei::xss", Tool: "nuclei", Severity: types.SeverityHigh,
		Title: "XSS", CWE: []string{"CWE-79"}, VerificationStatus: "verified",
	}}
	md := RenderVAPTMarkdown(ReportFromFindings(f, []string{"https://x"}, "Acme", time.Now().UTC(), nil))
	for _, bad := range []string{"ransomware", "weaponized:", "CISA remediation deadline", "Fix verification:"} {
		if strings.Contains(md, bad) {
			t.Errorf("clean report should not contain %q", bad)
		}
	}
}

// The retest roll-up is the "we prove the fix closed it" differentiator — counted from real
// FixVerification records the retester wrote, via the store path (VAPTReport method).
func TestVAPTReport_RetestRollup(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "web_application", Target: "https://acme.example"})
	_ = st.PutAction(ctx, platform.Action{ID: "act-1", TenantID: "t1", FindingID: "f-1",
		Kind: platform.ActOpenPR, Status: platform.ActApplied,
		Verification: &platform.FixVerification{Status: platform.FixStatusFixed}})
	_ = st.PutAction(ctx, platform.Action{ID: "act-2", TenantID: "t1", FindingID: "f-2",
		Kind: platform.ActOpenPR, Status: platform.ActApplied,
		Verification: &platform.FixVerification{Status: platform.FixStatusStillPresent}})
	_ = st.PutAction(ctx, platform.Action{ID: "act-3", TenantID: "t1", FindingID: "f-3",
		Kind: platform.ActOpenPR, Status: platform.ActPendingApproval}) // no verification → not counted

	g := &GRC{Store: st}
	r, err := g.VAPTReport(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.RetestConfirmed != 1 || r.Summary.RetestStillPresent != 1 {
		t.Fatalf("retest rollup = confirmed %d / still %d, want 1/1", r.Summary.RetestConfirmed, r.Summary.RetestStillPresent)
	}
	if !strings.Contains(RenderVAPTMarkdown(r), "Fix verification:** 1 applied fix re-tested and confirmed closed on re-scan; 1 still present") {
		t.Error("fix-verification line missing/wrong")
	}
}
