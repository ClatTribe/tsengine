package crossdetect

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestAnnotateCompensatingControls_BlockedOwnProbe(t *testing.T) {
	issues := []Issue{{Endpoint: "https://app.acme.com/search", Severity: "high"}}
	own := map[string]bool{"ourcanary": true}
	events := []platform.RuntimeEvent{
		{Endpoint: "https://app.acme.com/search", Marker: "ourcanary", Blocked: true, Source: "aws_waf"},
	}
	n := AnnotateCompensatingControls(issues, events, own)
	if n != 1 || !issues[0].WAFShielded {
		t.Fatalf("a blocked own-probe must annotate the issue: n=%d shielded=%v", n, issues[0].WAFShielded)
	}
	// HONESTY INVARIANT: severity is untouched, never downgraded, never marked fixed.
	if issues[0].Severity != "high" {
		t.Fatalf("severity must NOT change: got %q", issues[0].Severity)
	}
	if !strings.Contains(issues[0].WAFShieldReason, "NOT a fix") {
		t.Fatal("the reason must state it is not a fix")
	}
}

func TestAnnotateCompensatingControls_RequiresBlockedAndOwn(t *testing.T) {
	base := func() []Issue { return []Issue{{Endpoint: "https://app.acme.com/search", Severity: "high"}} }
	own := map[string]bool{"ourcanary": true}

	// Not blocked (monitor-only) => no compensating control.
	notBlocked := []platform.RuntimeEvent{{Endpoint: "https://app.acme.com/search", Marker: "ourcanary", Blocked: false}}
	if n := AnnotateCompensatingControls(base(), notBlocked, own); n != 0 {
		t.Fatal("a WAF that only COUNTED our probe is not a compensating control")
	}
	// Blocked, but NOT our probe (external attacker, foreign/empty marker) => not tied to our proof.
	foreign := []platform.RuntimeEvent{{Endpoint: "https://app.acme.com/search", Marker: "someoneelse", Blocked: true}}
	if n := AnnotateCompensatingControls(base(), foreign, own); n != 0 {
		t.Fatal("a blocked event that is not our probe must not annotate (grounded on our own proof)")
	}
	empty := []platform.RuntimeEvent{{Endpoint: "https://app.acme.com/search", Marker: "", Blocked: true}}
	if n := AnnotateCompensatingControls(base(), empty, own); n != 0 {
		t.Fatal("a blocked event with no marker is not tied to our probe")
	}
}

// The mirror property: the SAME own-probe event feeds compensating-controls (kept) but is filtered
// OUT of the production-attack signal (WithoutOwnProbes). One stream, two opposite consumers.
func TestCompensatingAndAttack_UseOppositeSidesOfOwnProbes(t *testing.T) {
	own := map[string]bool{"ourcanary": true}
	ev := []platform.RuntimeEvent{{Endpoint: "https://app.acme.com/x", Marker: "ourcanary", Blocked: true}}

	shielded := []Issue{{Endpoint: "https://app.acme.com/x"}}
	if AnnotateCompensatingControls(shielded, ev, own) != 1 {
		t.Fatal("compensating-controls consumes the RAW own-probe event")
	}
	attacked := []Issue{{Endpoint: "https://app.acme.com/x"}}
	filtered := WithoutOwnProbes(ev, own)
	if AnnotateRuntime(attacked, filtered) != 0 {
		t.Fatal("the same own-probe must NOT read as a production attack after filtering")
	}
	if attacked[0].Attacked {
		t.Fatal("our own blocked probe is not a production attack")
	}
}
