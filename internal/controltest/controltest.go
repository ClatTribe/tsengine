// Package controltest turns a customer's OWN perimeter controls into the sensor that answers the
// question detectionvalidation poses: when our pentest fired a real attack, did their defence see it,
// and did it BLOCK it?
//
// # Why this exists (ADR 0027, the control plane)
//
// internal/detectionvalidation already correlates our recorded probes against platform.RuntimeEvent.
// But a RuntimeEvent only ever arrived from an in-app RASP sensor a customer had to deploy — which
// our ICP (a team with no security staff) does not run. What that ICP DOES run is a WAF in front of
// their app: Cloudflare or AWS WAF. This package normalises a WAF's own logs into the same
// RuntimeEvent stream, so "did the WAF notice our SQLi, and did it block it?" is answerable with no
// new sensor — the WAF they already pay for becomes the control under test.
//
// # The join is the canary, and that is deliberate
//
// Our web pentest fires canaried traffic: a unique token in the URL (?q=<token>,
// ?url=http://canary.internal/<token>, ...). A WAF's sampled/dropped request carries that exact URL,
// so the WAF log can be tied to the precise probe that caused it — detectionvalidation's STRONG
// StrengthMarker tie, an exact one-alert-to-one-probe match rather than an inference from endpoint,
// class and timing. This matters here more than for a RASP sensor, because AttemptRecord.Method is
// "exploit" for every active probe (the vulnerability class is not recorded on the attempt), so the
// class-inference join cannot fire for pentest probes at all — the canary is the only working tie,
// and the WAF log is where our canary reappears.
//
// # Two honest boundaries (§10)
//
//   - BLOCKED is read from the control's OWN action verdict (WAF action == BLOCK), never inferred. A
//     COUNT/monitor-only rule that merely logged our attack is recorded Blocked:false — "it saw it"
//     and "it stopped it" are different answers and this package never lets one pass for the other.
//   - A WAF event with NO canary in the request is still stored, with Marker empty. It is not tied to
//     a probe, but it proves the WAF was alive and talking in that window — which is what lets
//     detectionvalidation move an unmatched probe from Undetermined ("we could not look") to
//     NotDetected ("the sensor was watching and did not report this"). Dropping those events would
//     silently weaken every miss verdict.
//
// The posted-snapshot path (a customer/CI pastes WAF logs) works today with no credential; the live
// pull (AWS WAFv2 GetSampledRequests, the Cloudflare firewall-events GraphQL/logpull API) is the
// credential-gated half, the same shape as the OSINT / SaaS-posture / CloudTrail ingests.
package controltest

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Source names for the RuntimeEvent (also the ?source= selector on the ingest).
const (
	SourceAWSWAF     = "aws_waf"
	SourceCloudflare = "cloudflare"
)

// markerIn returns the first canary that literally appears in any of the request parts, or "".
// Grounded: Marker is set ONLY when our own token is present — never guessed. An empty canary in the
// set is ignored so it cannot match every request.
func markerIn(canaries []string, parts ...string) string {
	joined := strings.Join(parts, "\n")
	for _, c := range canaries {
		c = strings.TrimSpace(c)
		if c != "" && strings.Contains(joined, c) {
			return c
		}
	}
	return ""
}

// attackKindFromLabels maps a WAF managed-rule label/name to the short attack-class vocabulary. It is
// human-facing context on the event; the probe join is by canary, not by this. An unrecognised label
// yields "" rather than a guess — an invented class on someone else's control is the kind of overclaim
// this package exists to avoid.
func attackKindFromLabels(labels ...string) string {
	s := strings.ToLower(strings.Join(labels, " "))
	switch {
	case containsAny(s, "sqli", "sql-database", "sql_injection", "sqlinjection"):
		return "sqli"
	case containsAny(s, "xss", "cross-site-scripting", "crosssitescripting"):
		return "xss"
	case containsAny(s, "ssrf"):
		return "ssrf"
	case containsAny(s, "lfi", "local-file", "path-traversal", "pathtraversal", "traversal"):
		return "path_traversal"
	case containsAny(s, "rce", "cmdi", "command-injection", "commandinjection"):
		return "rce"
	case containsAny(s, "rfi", "remote-file"):
		return "rfi"
	}
	return ""
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// blockedFromAction reports whether a control's action string means it intervened (vs merely logged).
// Conservative: only an explicit block/deny/drop counts. count / log / allow / challenge-that-passed
// are NOT a block — a CAPTCHA or JS challenge that the attacker could clear is not proof it stopped
// the attack, so it is recorded as observed-not-blocked rather than credited as a block.
func blockedFromAction(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	switch a {
	case "block", "blocked", "deny", "denied", "drop", "dropped":
		return true
	}
	return false
}

// normalized is the common result: the RuntimeEvent plus whether a record was usable at all.
func makeEvent(source, endpoint, kind, ip, marker, action string) platform.RuntimeEvent {
	return platform.RuntimeEvent{
		Source:     source,
		AttackKind: kind,
		Endpoint:   endpoint,
		SourceIP:   ip,
		Marker:     marker,
		Blocked:    blockedFromAction(action),
	}
}
