package types

import "strings"

// evidencerung.go is ADR 0029 D2d: ONE vocabulary for how strongly a finding is established.
//
// # The defect it closes
//
// VerificationStatus has three values, and "verified" had come to mean two materially different
// things depending on which producer set it:
//
//   - the offensive agent ran an exploit against the customer's live system and it worked;
//   - the cloud agent asked AWS's policy simulator, which allowed every hop — which confirms
//     AUTHORIZATION and explicitly NOT exploitability (ADR 0024 C1, and cloudinvestigate.go spends a
//     screen of comment saying so).
//
// Both render as the word "verified", including in the VAPT report a customer forwards to an
// auditor. That is the "rendered identically, X and Y are the same row" defect this codebase keeps
// naming, sitting in the artifact where it costs the most.
//
// # What a rung is
//
// A rung answers "WHAT DID WE DO to establish this?", not "how bad is it". That is deliberate: the
// acts are checkable and orderable, whereas a confidence scalar blends evidence with severity and a
// reader cannot tell which half moved.
//
//	exploited              we attacked it and it worked
//	provider_confirmed     we asked the authority and it said yes
//	reachability_confirmed we analysed your code and found the path to it
//	corroborated           two independent tools agreed
//	scanner_reported       one tool matched a pattern
//
// # What it deliberately does not do
//
// It never invents evidence. Everything below is read from what a producer already recorded, and a
// finding with nothing recorded lands on the floor rather than on a guess. It is also NOT a severity
// or a priority: an exploited low and a scanner-reported critical are both exactly what they say.
type EvidenceRung string

// pocMarker is the prefix the active driver writes when a demonstration succeeded. grc/vapt.go
// splits the report's PoC block on the same string; if it ever moves, both move together.
const pocMarker = "[Exploitation PoC"

const (
	// RungExploited: a demonstration ran against the live target and its predicate held. The only
	// rung that claims exploitability.
	RungExploited EvidenceRung = "exploited"
	// RungProviderConfirmed: the system's own authority — a cloud provider's policy evaluator —
	// was asked and allowed it. Confirms AUTHORIZATION, never exploitability.
	RungProviderConfirmed EvidenceRung = "provider_confirmed"
	// RungReachabilityConfirmed: static analysis of THIS repository found a path from an entrypoint
	// to the vulnerable dependency. Evidence about the customer's code, not about the world.
	RungReachabilityConfirmed EvidenceRung = "reachability_confirmed"
	// RungCorroborated: at least two independent tools reported the same thing. Agreement, not proof.
	RungCorroborated EvidenceRung = "corroborated"
	// RungScannerReported: one tool matched a pattern. The honest floor, and where most findings sit.
	RungScannerReported EvidenceRung = "scanner_reported"
)

// Label is the phrase a human reads. It states the ACT, so the reader is never left to infer how
// much was actually done.
func (r EvidenceRung) Label() string {
	switch r {
	case RungExploited:
		return "exploited — we ran the attack and it worked"
	case RungProviderConfirmed:
		return "provider-confirmed — your cloud provider's own policy evaluator allowed every step (authorization, not exploitation)"
	case RungReachabilityConfirmed:
		return "reachable in your code — a call path was found from an entrypoint to this dependency"
	case RungCorroborated:
		return "corroborated — two or more independent tools reported it"
	default:
		return "reported by one scanner — a lead to validate, not a demonstrated exploit"
	}
}

// ClaimsExploitability reports whether this rung entitles anyone to say the issue is exploitable.
// Exactly one rung does. It exists so a caller cannot accidentally treat "verified" as that claim,
// which is the mistake the whole file is here to prevent.
func (r EvidenceRung) ClaimsExploitability() bool { return r == RungExploited }

// Rung reports the strongest thing we can honestly say about how this finding was established.
//
// Order matters and is by ACT, not by confidence: attacking something outranks asking the provider
// about it, which outranks analysing the code, which outranks two scanners agreeing.
func (f Finding) Rung() EvidenceRung {
	// 1. Exploited. A captured proof-of-concept is the artifact a demonstration leaves behind, and
	//    nothing else in the system produces one — the active driver appends it only when the
	//    predicate held. The verification state alone is NOT sufficient here: that is the exact
	//    conflation this replaces.
	if strings.Contains(f.Description, pocMarker) || strings.Contains(string(f.RawOutput), pocMarker) {
		return RungExploited
	}
	if f.VerificationStatus == VerificationVerified && isOffensiveProducer(f.Tool) {
		return RungExploited
	}

	// 2. Provider-confirmed. The cloud agent reaches `verified` only when the provider's simulator
	//    allowed every hop (authorizationRungStatus); no other producer sets that combination.
	if f.VerificationStatus == VerificationVerified {
		return RungProviderConfirmed
	}

	// 3. Reachability. Recorded by the runner's triage over the repository's own call graph. Only a
	//    positive counts: "no path found" is a priority signal and says nothing about how the finding
	//    was established.
	if f.ToolArgs["reachability"] == "reachable" {
		return RungReachabilityConfirmed
	}

	if f.VerificationStatus == VerificationCorroborated {
		return RungCorroborated
	}
	return RungScannerReported
}

// isOffensiveProducer names the tools whose `verified` means an exploit ran. Kept as a closed list
// rather than a heuristic on the name: a new producer must be added here deliberately, because
// joining this list is how a finding starts claiming exploitability.
func isOffensiveProducer(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "web-investigate", "pentest", "webagent":
		return true
	default:
		return false
	}
}
