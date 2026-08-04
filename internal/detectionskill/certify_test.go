package detectionskill

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

var at = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

func mappedFindings() []types.Finding {
	return []types.Finding{
		{ID: "f-001", RuleID: "operate::stale-account", Compliance: &types.Compliance{
			SOC2: []string{"CC6.1", "CC6.2"}, ISO27001: []string{"A.5.16"},
		}},
		{ID: "f-002", RuleID: "operate::admin-without-mfa", Compliance: &types.Compliance{
			SOC2: []string{"CC6.1"}, NIST80053: []string{"IA-2"}, // CC6.1 duplicates f-001 on purpose
		}},
		{ID: "f-003", RuleID: "misc::unmapped"}, // no compliance mapping at all
	}
}

func TestCertify_InheritsControlsFromCitedFindings(t *testing.T) {
	r := Result{Verdict: VerdictSuspicious, Evidence: []string{"f-001", "f-002"},
		Rationale: "privileged binding survived suspension", SkillName: "s", SkillDigest: "deadbeefcafe0000"}

	c, err := Certify(r, mappedFindings(), at)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Controls.SOC2; !reflect.DeepEqual(got, []string{"CC6.1", "CC6.2"}) {
		t.Errorf("SOC2 controls should be the deduped, sorted union, got %v", got)
	}
	if got := c.Controls.NIST80053; !reflect.DeepEqual(got, []string{"IA-2"}) {
		t.Errorf("NIST 800-53 should carry through, got %v", got)
	}
	if c.ControlCount() != 4 { // CC6.1, CC6.2, A.5.16, IA-2
		t.Errorf("ControlCount = %d, want 4", c.ControlCount())
	}
	if fw := c.Frameworks(); len(fw) != 3 {
		t.Errorf("expected 3 frameworks touched, got %v", fw)
	}
}

// THE grounding property: a certification may only ever speak to controls that came from findings the
// engine actually emitted. A skill has no channel through which to supply one.
func TestCertify_NeverInventsControls(t *testing.T) {
	r := Result{Verdict: VerdictMalicious, Evidence: []string{"f-003"}, SkillName: "s"} // f-003 is unmapped
	c, err := Certify(r, mappedFindings(), at)
	if err != nil {
		t.Fatal(err)
	}
	if c.Controls != nil {
		t.Fatalf("an unmapped finding must yield NO controls, got %+v", c.Controls)
	}
	if c.ControlCount() != 0 {
		t.Errorf("ControlCount should be 0, got %d", c.ControlCount())
	}
	// And it must SAY so rather than presenting itself as compliance evidence.
	if !strings.Contains(c.Summary(), "no control mapping") {
		t.Errorf("summary must be honest about the absent mapping: %q", c.Summary())
	}
}

// A benign verdict is still evidence — "we assessed this control and found no violation" is what an
// auditor wants. Discarding it would throw away half the value of running the skill.
func TestCertify_BenignVerdictStillCertifies(t *testing.T) {
	r := Result{Verdict: VerdictBenign, Evidence: []string{"f-001"}, SkillName: "s"}
	c, err := Certify(r, mappedFindings(), at)
	if err != nil {
		t.Fatal(err)
	}
	if c.Verdict != VerdictBenign || c.ControlCount() == 0 {
		t.Fatalf("a benign assessment should still record the controls it covered: %+v", c)
	}
}

func TestCertify_RefusesEvidenceNotSupplied(t *testing.T) {
	r := Result{Verdict: VerdictMalicious, Evidence: []string{"f-999"}, SkillName: "s"}
	if _, err := Certify(r, mappedFindings(), at); err == nil {
		t.Fatal("certifying against a finding that was not supplied must be refused")
	}
}

func TestCertify_RefusesEmptyVerdict(t *testing.T) {
	if _, err := Certify(Result{Evidence: []string{"f-001"}}, mappedFindings(), at); err == nil {
		t.Fatal("an empty verdict must not certify")
	}
}

// --- human accountability (§18.4: the engine proposes, a named human disposes) ---

func TestCertification_IsProposedUntilAttested(t *testing.T) {
	r := Result{Verdict: VerdictSuspicious, Evidence: []string{"f-001"}, SkillName: "s", SkillDigest: "abc123def456"}
	c, _ := Certify(r, mappedFindings(), at)

	if c.Attested() {
		t.Fatal("a fresh certification must NOT be attested — the engine cannot sign for a human")
	}
	if !strings.Contains(c.Summary(), "proposed (unattested)") {
		t.Errorf("an unattested certification must say so: %q", c.Summary())
	}

	signed, err := c.Attest("Ada Fernandez", at)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.Attested() || signed.AttestedBy != "Ada Fernandez" || signed.AttestedAt.IsZero() {
		t.Fatalf("attestation not recorded: %+v", signed)
	}
	if !strings.Contains(signed.Summary(), "attested by Ada Fernandez") {
		t.Errorf("summary should name the accountable human: %q", signed.Summary())
	}
	// Attest must not mutate the original — a proposal and its attested form are distinct records.
	if c.Attested() {
		t.Error("Attest must return a new value, not mutate the proposal")
	}
}

func TestCertification_RefusesUnnamedAttestation(t *testing.T) {
	c, _ := Certify(Result{Verdict: VerdictBenign, Evidence: []string{"f-001"}, SkillName: "s"}, mappedFindings(), at)
	for _, who := range []string{"", "   ", "\t"} {
		if _, err := c.Attest(who, at); err == nil {
			t.Errorf("attestation by %q must be refused — that is not accountability", who)
		}
	}
}

// Drift guard: §8 already requires a new framework in four places. The union must not become a fifth
// that silently forgets one, so it is reflection-driven — this asserts every framework field is
// visited.
func TestUnionCoversEveryFramework(t *testing.T) {
	full := &types.Compliance{}
	v := reflect.ValueOf(full).Elem()
	tp := v.Type()
	var expected []string
	for i := 0; i < tp.NumField(); i++ {
		if tp.Field(i).Type.Kind() == reflect.Slice && tp.Field(i).Type.Elem().Kind() == reflect.String {
			v.Field(i).Set(reflect.ValueOf([]string{"X-1"}))
			expected = append(expected, tp.Field(i).Name)
		}
	}
	if len(expected) < 20 {
		t.Fatalf("expected the full framework set on types.Compliance, found %d", len(expected))
	}

	got := unionCompliance([]types.Finding{{ID: "f", Compliance: full}})
	if got == nil {
		t.Fatal("union dropped every framework")
	}
	c := Certification{Controls: got}
	if len(c.Frameworks()) != len(expected) {
		t.Fatalf("union covered %d frameworks, want all %d — a new framework would be silently dropped",
			len(c.Frameworks()), len(expected))
	}
	if c.ControlCount() != len(expected) {
		t.Errorf("ControlCount = %d, want %d", c.ControlCount(), len(expected))
	}
}

func TestUnionIsDeterministic(t *testing.T) {
	fs := mappedFindings()
	a := unionCompliance(fs)
	b := unionCompliance(fs)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("the same evidence must render identically every run (§10)")
	}
}
