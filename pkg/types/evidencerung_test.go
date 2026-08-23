package types

import "testing"

// evidencerung_test.go is ADR 0029 D2d. The load-bearing test is the FIRST one: two findings that
// used to be indistinguishable must now be distinguishable, in the artifact a customer forwards.

func TestRung_ExploitedAndProviderConfirmedAreNotTheSameClaim(t *testing.T) {
	// Both of these are stored with VerificationStatus "verified". That is correct for each producer
	// and it is why the word alone cannot be the vocabulary.
	exploited := Finding{
		Tool: "web-investigate", RuleID: "web-agent::sqli", VerificationStatus: VerificationVerified,
		Description: "boolean differential reached the database\n\n[Exploitation PoC] GET /search?q=…",
	}
	authorized := Finding{
		Tool: "cloudagent", RuleID: "cloudagent::privilege-escalation", VerificationStatus: VerificationVerified,
		Description: "role can reach admin; every hop allowed by the provider's simulator",
	}

	if exploited.Rung() != RungExploited {
		t.Errorf("an exploit with a captured PoC is %q, want %q", exploited.Rung(), RungExploited)
	}
	if authorized.Rung() != RungProviderConfirmed {
		t.Errorf("a provider-simulated cloud path is %q, want %q", authorized.Rung(), RungProviderConfirmed)
	}
	if exploited.Rung() == authorized.Rung() {
		t.Fatal("the two rungs are identical. One of these was attacked and one was asked about; " +
			"rendering them the same is the defect ADR 0029 D2d exists to close.")
	}
	if !exploited.Rung().ClaimsExploitability() {
		t.Error("an exploited finding must be allowed to claim exploitability")
	}
	if authorized.Rung().ClaimsExploitability() {
		t.Error("a provider-confirmed AUTHORIZATION must never claim exploitability (ADR 0024 C1). " +
			"This is the single most important assertion in this file.")
	}
	if exploited.Rung().Label() == authorized.Rung().Label() {
		t.Error("the two labels read identically to a human, which is where the claim is actually made")
	}
}

func TestRung_TheLadder(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want EvidenceRung
	}{
		{
			name: "a PoC outranks everything",
			f:    Finding{Tool: "nuclei", VerificationStatus: VerificationCorroborated, Description: "x\n[Exploitation PoC] …"},
			want: RungExploited,
		},
		{
			name: "the offensive agent's verified means exploited even without a PoC in the description",
			f:    Finding{Tool: "web-investigate", VerificationStatus: VerificationVerified},
			want: RungExploited,
		},
		{
			name: "any other producer's verified is provider-confirmed, not exploited",
			f:    Finding{Tool: "cloudagent", VerificationStatus: VerificationVerified},
			want: RungProviderConfirmed,
		},
		{
			name: "a reachable dependency outranks two scanners agreeing",
			f: Finding{Tool: "osv-scanner", VerificationStatus: VerificationCorroborated,
				ToolArgs: map[string]string{"reachability": "reachable"}},
			want: RungReachabilityConfirmed,
		},
		{
			name: "an UNREACHABLE dependency says nothing about how it was established",
			f: Finding{Tool: "osv-scanner", VerificationStatus: VerificationCorroborated,
				ToolArgs: map[string]string{"reachability": "unused"}},
			want: RungCorroborated,
		},
		{
			name: "corroboration alone",
			f:    Finding{Tool: "trivy", VerificationStatus: VerificationCorroborated},
			want: RungCorroborated,
		},
		{
			name: "the floor",
			f:    Finding{Tool: "semgrep", VerificationStatus: VerificationPatternMatch},
			want: RungScannerReported,
		},
		{
			name: "a finding with nothing recorded lands on the floor, never on a guess",
			f:    Finding{},
			want: RungScannerReported,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.Rung(); got != tc.want {
				t.Errorf("rung = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRung_OnlyExploitedClaimsExploitability(t *testing.T) {
	// Stated as its own test because it is the property every caller relies on, and because a future
	// rung added to the ladder must make this choice deliberately rather than by position.
	for _, r := range []EvidenceRung{
		RungProviderConfirmed, RungReachabilityConfirmed, RungCorroborated, RungScannerReported,
	} {
		if r.ClaimsExploitability() {
			t.Errorf("%q claims exploitability. Only an exploit that ran may do that.", r)
		}
		if r.Label() == "" {
			t.Errorf("%q has no human label — an unlabelled rung renders as a bare enum in a customer document", r)
		}
	}
}

func TestRung_OffensiveProducerListIsClosed(t *testing.T) {
	// A tool joining this list is how a finding starts claiming exploitability, so it must not be
	// reachable by a name that merely looks offensive.
	for _, tool := range []string{"nuclei", "sqlmap", "dalfox", "grype", "web-investigator", "pentester"} {
		f := Finding{Tool: tool, VerificationStatus: VerificationVerified}
		if f.Rung() == RungExploited {
			t.Errorf("%q was treated as an offensive producer. Membership must be a deliberate entry in "+
				"the list, not a resemblance to one of the names in it.", tool)
		}
	}
}
