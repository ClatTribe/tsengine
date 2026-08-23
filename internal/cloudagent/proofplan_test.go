package cloudagent

import "testing"

func chk(status HopStatus) RequiredCheck { return RequiredCheck{Status: status} }

// The two strong verdicts are ASYMMETRIC by design: ALL hops for a confirmation, ANY hop for a
// refusal. A chain is as strong as its weakest link and as broken as its most broken one.
func TestRollUp(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks []RequiredCheck
		want   PathStatus
	}{
		{"every hop confirmed", []RequiredCheck{chk(HopConfirmed), chk(HopConfirmed)}, PathConfirmed},
		// THE DEFECT THE RATIO HID. Before the plan, a denied hop counted as merely "not confirmed",
		// so this rendered "1/2 confirmed" — partial evidence the path is OPEN, computed from
		// authoritative evidence that it is not.
		{"one denied hop refutes the path", []RequiredCheck{chk(HopConfirmed), chk(HopDenied)}, PathDenied},
		{"a denial outranks everything else", []RequiredCheck{chk(HopDenied), chk(HopConfirmed), chk(HopUnknown)}, PathDenied},
		{"some confirmed, rest unresolved", []RequiredCheck{chk(HopConfirmed), chk(HopUnknown)}, PathPartial},
		{"nothing established either way", []RequiredCheck{chk(HopUnknown), chk(HopUntested)}, PathUnknown},
		{"no authorization-requiring hops", nil, PathUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rollUp(tc.checks); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// A HOP is a disjunction — any permitted action traverses it — which is the OPPOSITE of the
// path-level rule and correct for the opposite reason. A hop where iam:PassRole was denied but
// sts:AssumeRole was allowed is walkable, and calling it denied would refute a path an attacker can
// actually take.
func TestHopStatus_AllowWinsOverDenyWithinAHop(t *testing.T) {
	cc := &Context{probes: map[string]ProbeResult{
		confirmKey("p", "iam:PassRole", "r"):   {Verdict: VerdictDeny, Detail: "explicit deny"},
		confirmKey("p", "sts:AssumeRole", "r"): {Verdict: VerdictAllow, Detail: "allowed by TrustPolicy"},
	}}
	got, detail, _ := cc.hopStatus("p", "r")
	if got != HopConfirmed {
		t.Fatalf("hop = %q, want confirmed — one denied action does not close a hop another action opens", got)
	}
	if detail == "" {
		t.Error("the allowing statement must be cited, or the confirmation cannot be audited")
	}
}

// "We ran out of budget" and "the provider refused to say" are different facts about our coverage.
// The ratio merged them; a reader chasing a gap needs to know which one they have.
func TestHopStatus_UntestedIsNotUnknown(t *testing.T) {
	cc := &Context{probes: map[string]ProbeResult{
		confirmKey("p", "s3:GetObject", "r"): {Verdict: VerdictUnknown, Why: "throttled"},
	}}
	if got, _, why := cc.hopStatus("p", "r"); got != HopUnknown || why != "throttled" {
		t.Fatalf("asked-but-unanswered = %q (%s), want unknown carrying its reason", got, why)
	}
	if got, _, why := cc.hopStatus("other", "elsewhere"); got != HopUntested || why != "" {
		t.Fatalf("never-asked = %q (%s), want untested with nothing to explain", got, why)
	}
}

// A denied hop is only denied for the actions we ASKED about. It must cite the provider's words, or
// the strongest negative claim in the system rests on our say-so.
func TestHopStatus_ADeniedHopCitesTheProvider(t *testing.T) {
	cc := &Context{probes: map[string]ProbeResult{
		confirmKey("p", "s3:GetObject", "r"): {Verdict: VerdictDeny, Detail: "explicit deny (DenyExports)"},
	}}
	got, detail, _ := cc.hopStatus("p", "r")
	if got != HopDenied || detail != "explicit deny (DenyExports)" {
		t.Fatalf("hop = %q detail = %q, want a denial citing the provider", got, detail)
	}
}

// The short form C2 introduced must keep working for renderers that use it.
func TestCoverage_KeepsTheC2ShortForm(t *testing.T) {
	p := AuthorizationProofPlan{Confirmed: 2, Required: 5}
	if p.Coverage() != "2/5" {
		t.Fatalf("coverage = %q, want 2/5", p.Coverage())
	}
	if (AuthorizationProofPlan{}).Coverage() != "0/0" {
		t.Fatal("an empty plan must render 0/0, the value the rung line already treats as no-proof")
	}
}
