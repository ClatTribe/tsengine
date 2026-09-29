package controltest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// FromAWSWAF normalises one AWS WAFv2 sampled request (the shape GetSampledRequests returns in
// SampledHTTPRequests[]) into a RuntimeEvent. canaries is the set of active probe tokens to look for
// in the request line; when one is present the event carries it as the STRONG marker tie.
//
// Grounded (§10): Blocked comes from the WAF's own Action verdict; AttackKind from its matched
// managed-rule Labels; the marker only when our token literally appears in the URI. A record with no
// eventName-equivalent (no URI and no rule) is dropped and reported false, never guessed at.
func FromAWSWAF(raw []byte, canaries []string) (platform.RuntimeEvent, bool) {
	var rec struct {
		Action    string `json:"Action"`
		Timestamp int64  `json:"Timestamp"` // epoch millis (WAF sampled-request convention)
		RuleName  string `json:"RuleNameWithinRuleGroup"`
		Request   struct {
			ClientIP string `json:"ClientIP"`
			URI      string `json:"URI"`
			Method   string `json:"Method"`
			Headers  []struct {
				Name  string `json:"Name"`
				Value string `json:"Value"`
			} `json:"Headers"`
		} `json:"Request"`
		Labels []struct {
			Name string `json:"Name"`
		} `json:"Labels"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return platform.RuntimeEvent{}, false
	}
	if strings.TrimSpace(rec.Request.URI) == "" && strings.TrimSpace(rec.RuleName) == "" {
		return platform.RuntimeEvent{}, false // nothing to correlate or classify on
	}
	var labelNames []string
	for _, l := range rec.Labels {
		labelNames = append(labelNames, l.Name)
	}
	// Host header lets the endpoint read as a real URL rather than a bare path.
	host := ""
	for _, h := range rec.Request.Headers {
		if strings.EqualFold(h.Name, "host") {
			host = h.Value
			break
		}
	}
	endpoint := rec.Request.URI
	if host != "" && strings.HasPrefix(endpoint, "/") {
		endpoint = host + endpoint
	}
	kind := attackKindFromLabels(append(labelNames, rec.RuleName)...)
	marker := markerIn(canaries, rec.Request.URI, host)

	ev := makeEvent(SourceAWSWAF, endpoint, kind, rec.Request.ClientIP, marker, rec.Action)
	ev.App = strings.TrimSpace(rec.RuleName)
	if rec.Timestamp > 0 {
		ev.OccurredAt = time.UnixMilli(rec.Timestamp).UTC()
	}
	return ev, true
}

// FromCloudflare normalises one Cloudflare firewall event (the shape firewallEventsAdaptive /
// the firewall-events logpull returns) into a RuntimeEvent.
//
// Cloudflare's action vocabulary is richer: block / managed_challenge / js_challenge / challenge /
// log / allow / skip. Only an outright block counts as an intervention (blockedFromAction); a
// challenge is NOT a block, because an attacker (or a headless solver) that clears it still reaches
// the app — crediting a challenge as a block would tell the customer they are protected when the
// attack still lands.
func FromCloudflare(raw []byte, canaries []string) (platform.RuntimeEvent, bool) {
	var rec struct {
		Action   string `json:"action"`
		Datetime string `json:"datetime"`
		ClientIP string `json:"clientIP"`
		Host     string `json:"clientRequestHTTPHost"`
		Path     string `json:"clientRequestPath"`
		Query    string `json:"clientRequestQuery"`
		Source   string `json:"source"` // the CF product that fired: waf / firewallmanaged / ...
		RuleID   string `json:"ruleId"`
		RuleMsg  string `json:"description"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return platform.RuntimeEvent{}, false
	}
	if strings.TrimSpace(rec.Path) == "" && strings.TrimSpace(rec.RuleID) == "" {
		return platform.RuntimeEvent{}, false
	}
	endpoint := rec.Host + rec.Path
	if rec.Query != "" {
		endpoint += rec.Query
	}
	kind := attackKindFromLabels(rec.RuleMsg, rec.RuleID, rec.Source)
	marker := markerIn(canaries, rec.Path, rec.Query, rec.Host)

	ev := makeEvent(SourceCloudflare, endpoint, kind, rec.ClientIP, marker, rec.Action)
	ev.App = strings.TrimSpace(rec.Source)
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(rec.Datetime)); err == nil {
		ev.OccurredAt = t.UTC()
	}
	return ev, true
}

// NormalizeWAF maps a batch of raw WAF records for one source into RuntimeEvents, returning the
// events it could parse and the count it could not (dropped, never guessed at — the caller reports
// the drop count so a half-readable snapshot cannot masquerade as a clean one).
func NormalizeWAF(source string, records []json.RawMessage, canaries []string) (events []platform.RuntimeEvent, dropped int) {
	parse := FromAWSWAF
	if source == SourceCloudflare {
		parse = FromCloudflare
	}
	for _, rc := range records {
		if ev, ok := parse(rc, canaries); ok {
			events = append(events, ev)
		} else {
			dropped++
		}
	}
	return events, dropped
}
