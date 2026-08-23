package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE property: a class whose real fix is a CODE change also carries something that reduces exposure
// today, alongside the fix rather than instead of it.
func TestPropose_CodeChangeClassesCarryAnInterimMitigation(t *testing.T) {
	f := types.Finding{ID: "f1", Title: "SQL injection in search", CWE: []string{"CWE-89"},
		Severity: types.SeverityHigh, Endpoint: "https://app/search"}
	act, _ := Propose(f, webAsset("web_application"), ids())

	if act.Payload["interim_mitigation_type"] != mitigateAtEdge {
		t.Fatalf("want an edge mitigation, got %v", act.Payload["interim_mitigation_type"])
	}
	steps, _ := act.Payload["interim_mitigation"].(string)
	if !strings.Contains(steps, "WAF") {
		t.Errorf("the mitigation must name the control it needs, got: %s", steps)
	}
	// It rides ALONGSIDE the real fix — never replacing it.
	rem, _ := act.Payload["remediation"].(string)
	if !strings.Contains(rem, "PARAMETERISED") {
		t.Errorf("the actual fix must still be present, got: %s", rem)
	}
}

// THE refusal that makes it safe to show. A customer who applies a WAF rule and watches the finding
// disappear will believe the bug is gone. Every mitigation must say, in the text itself, that it does
// not fix or close anything.
func TestInterimMitigation_NeverPresentsItselfAsAFix(t *testing.T) {
	types_ := []string{rtypeParameterizeQuery, rtypeEncodeOutput, rtypeSSRFAllowlist,
		rtypeRedirectAllowlist, rtypePathCanonicalize, rtypeAvoidShellExec,
		rtypeRemoveExposedFile, rtypeEnforceObjectAuthz}
	for _, rt := range types_ {
		mt, steps, ok := interimMitigation(rt)
		if !ok {
			t.Errorf("%s: expected an interim mitigation", rt)
			continue
		}
		if mt == "" || strings.TrimSpace(steps) == "" {
			t.Errorf("%s: empty mitigation", rt)
		}
		if !strings.Contains(steps, "does NOT fix") || !strings.Contains(steps, "does not close this finding") {
			t.Errorf("%s: a mitigation must say it neither fixes nor closes, got: %s", rt, steps)
		}
		if !strings.Contains(steps, "stays open") {
			t.Errorf("%s: must say the finding stays open, got: %s", rt, steps)
		}
	}
}

// Classes whose fix is ITSELF a config change get nothing: for those, "mitigate now" and "fix" are
// the same act, and a second-best version would be noise.
func TestInterimMitigation_NotOfferedWhereTheFixIsAlreadyImmediate(t *testing.T) {
	for _, rt := range []string{rtypeRotateDefaultCreds, rtypeTLSHardening, rtypeSecurityHeaders,
		rtypePackageUpgrade, rtypeBaseImageUpgrade, rtypeImageSigning, rtypeContainerHardening,
		rtypeGraphQLIntrospect} {
		if _, _, ok := interimMitigation(rt); ok {
			t.Errorf("%s: fix is already immediate — offering an interim is noise", rt)
		}
	}
	// And an unrecognised class invents nothing.
	if _, _, ok := interimMitigation("something_new"); ok {
		t.Error("an unknown class must not be given an invented mitigation")
	}
}

// It must never touch the finding's standing. A mitigation that could downgrade or resolve would be
// the false confidence this whole layer exists to prevent.
func TestPropose_InterimMitigationChangesNothingAboutTheAction(t *testing.T) {
	f := types.Finding{ID: "f1", Title: "SSRF in webhook", CWE: []string{"CWE-918"},
		Severity: types.SeverityCritical, Endpoint: "https://app/hook"}
	withM, _ := Propose(f, webAsset("web_application"), ids())
	if withM.Tier != 1 || withM.Status != "proposed" {
		t.Errorf("a mitigation must not alter tier or status, got tier=%d status=%s", withM.Tier, withM.Status)
	}
	if withM.Payload["remediation_type"] != rtypeSSRFAllowlist {
		t.Errorf("the fix class must be unchanged, got %v", withM.Payload["remediation_type"])
	}
}
