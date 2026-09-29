package controltest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/detectionvalidation"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

const canary = "ts7f3a91canary"

// A real-shaped AWS WAFv2 sampled request that BLOCKED our canaried SQLi probe.
func awsWAFBlockedSQLi() []byte {
	return []byte(`{
      "Action": "BLOCK",
      "Timestamp": 1750000000000,
      "RuleNameWithinRuleGroup": "AWS-AWSManagedRulesSQLiRuleSet",
      "Request": {
        "ClientIP": "203.0.113.9",
        "URI": "/search?q=` + canary + `%27%20OR%201%3D1",
        "Method": "GET",
        "Headers": [{"Name": "Host", "Value": "app.acme.com"}]
      },
      "Labels": [{"Name": "awswaf:managed:aws:sql-database:SQLi_QueryArguments"}]
    }`)
}

func TestFromAWSWAF_BlockedCanary(t *testing.T) {
	ev, ok := FromAWSWAF(awsWAFBlockedSQLi(), []string{canary})
	if !ok {
		t.Fatal("expected a usable event")
	}
	if ev.Marker != canary {
		t.Fatalf("marker: want %q got %q — the canary is in the URI, must be the strong tie", canary, ev.Marker)
	}
	if !ev.Blocked {
		t.Fatal("Action BLOCK must record Blocked:true — this is the 'did the WAF stop it' answer")
	}
	if ev.AttackKind != "sqli" {
		t.Fatalf("attack kind from SQLi label: want sqli got %q", ev.AttackKind)
	}
	if ev.Endpoint != "app.acme.com/search?q="+canary+"%27%20OR%201%3D1" {
		t.Fatalf("endpoint host-joined wrong: %q", ev.Endpoint)
	}
	if ev.Source != SourceAWSWAF {
		t.Fatalf("source: %q", ev.Source)
	}
}

// COUNT (monitor-only) must NOT read as blocked — "saw it" is not "stopped it".
func TestFromAWSWAF_CountIsNotBlocked(t *testing.T) {
	raw := []byte(`{"Action":"COUNT","Timestamp":1750000000000,
      "Request":{"ClientIP":"203.0.113.9","URI":"/search?q=` + canary + `","Method":"GET",
      "Headers":[{"Name":"Host","Value":"app.acme.com"}]},
      "Labels":[{"Name":"awswaf:managed:aws:sql-database:SQLi_QueryArguments"}]}`)
	ev, ok := FromAWSWAF(raw, []string{canary})
	if !ok {
		t.Fatal("usable")
	}
	if ev.Blocked {
		t.Fatal("COUNT is monitor-only; must be Blocked:false")
	}
	if ev.Marker != canary {
		t.Fatal("still tied by canary even in count mode")
	}
}

// A record with our canary absent is still usable (proves the WAF was alive) but carries no marker.
func TestFromAWSWAF_NoCanaryStillAlive(t *testing.T) {
	raw := []byte(`{"Action":"BLOCK","Timestamp":1750000000000,
      "Request":{"ClientIP":"198.51.100.7","URI":"/login?x=someoneelse","Method":"POST",
      "Headers":[{"Name":"Host","Value":"app.acme.com"}]},
      "Labels":[{"Name":"awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"}]}`)
	ev, ok := FromAWSWAF(raw, []string{canary})
	if !ok {
		t.Fatal("a WAF event with no canary is still stored (aliveness signal)")
	}
	if ev.Marker != "" {
		t.Fatalf("must not invent a marker: got %q", ev.Marker)
	}
	if ev.AttackKind != "xss" {
		t.Fatalf("xss label: got %q", ev.AttackKind)
	}
}

func TestFromCloudflare_BlockedCanary(t *testing.T) {
	raw := []byte(`{
      "action": "block",
      "datetime": "2025-06-15T12:00:05Z",
      "clientIP": "203.0.113.9",
      "clientRequestHTTPHost": "app.acme.com",
      "clientRequestPath": "/item",
      "clientRequestQuery": "?url=http://canary.internal/` + canary + `",
      "source": "waf",
      "ruleId": "100015",
      "description": "SSRF - Server Side Request Forgery"
    }`)
	ev, ok := FromCloudflare(raw, []string{canary})
	if !ok {
		t.Fatal("usable")
	}
	if ev.Marker != canary {
		t.Fatalf("canary in query must tie: got %q", ev.Marker)
	}
	if !ev.Blocked {
		t.Fatal("action block => Blocked")
	}
	if ev.AttackKind != "ssrf" {
		t.Fatalf("ssrf from description: got %q", ev.AttackKind)
	}
}

// A Cloudflare challenge is NOT a block (an attacker can clear it).
func TestFromCloudflare_ChallengeIsNotBlock(t *testing.T) {
	raw := []byte(`{"action":"managed_challenge","datetime":"2025-06-15T12:00:05Z",
      "clientRequestHTTPHost":"app.acme.com","clientRequestPath":"/x","clientRequestQuery":"?q=` + canary + `",
      "source":"waf","ruleId":"1"}`)
	ev, ok := FromCloudflare(raw, []string{canary})
	if !ok {
		t.Fatal("usable")
	}
	if ev.Blocked {
		t.Fatal("a challenge is not a block")
	}
}

func TestNormalizeWAF_ReportsDropped(t *testing.T) {
	recs := []json.RawMessage{
		json.RawMessage(awsWAFBlockedSQLi()),
		json.RawMessage(`{"garbage":true}`), // no URI, no rule -> dropped
		json.RawMessage(`not json`),         // unparseable -> dropped
	}
	evs, dropped := NormalizeWAF(SourceAWSWAF, recs, []string{canary})
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if dropped != 2 {
		t.Fatalf("want 2 dropped (never guessed), got %d", dropped)
	}
}

// End-to-end: the normalized WAF event, fed to detectionvalidation against the very probe that
// carried the canary, yields a MARKER-strength detection with Blocked surfaced. This is the whole
// point — "did the WAF catch and block our proven SQLi?" answered exactly.
func TestEndToEnd_WAFDetectsProvenProbe(t *testing.T) {
	fired := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	attempts := []pentest.AttemptRecord{{
		Target: "app.acme.com/search", Method: "exploit", Allowed: true, Proven: true,
		Canary: canary, At: fired,
	}}
	probes := detectionvalidation.ProbesFrom(attempts)

	ev, _ := FromAWSWAF(awsWAFBlockedSQLi(), []string{canary})
	ev.OccurredAt = fired.Add(2 * time.Second) // within window
	rep := detectionvalidation.Validate(probes, []platform.RuntimeEvent{ev}, 0)

	if len(rep.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Verdict != detectionvalidation.Detected {
		t.Fatalf("want detected, got %q (%s)", r.Verdict, r.Why)
	}
	if r.Strength != detectionvalidation.StrengthMarker {
		t.Fatalf("want marker strength (exact canary tie), got %q", r.Strength)
	}
	if !r.Blocked {
		t.Fatal("the WAF blocked it; the report must say so")
	}
}
