package notify

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func policyOf(p *platform.EscalationPolicy) PolicyResolver {
	return func(context.Context, string) *platform.EscalationPolicy { return p }
}

// A new incident routes ONLY to the channels named in the first matching tier — severity-aware.
func TestPolicyRouter_RoutesBySeverity(t *testing.T) {
	pol := &platform.EscalationPolicy{Enabled: true, Tiers: []platform.EscalationTier{
		{MinSeverity: "critical", Channels: []string{"pagerduty", "slack"}},
		{MinSeverity: "high", Channels: []string{"slack"}},
	}}

	t.Run("critical → pagerduty+slack, not default", func(t *testing.T) {
		pd, slack, def := &recordingAlerter{}, &recordingAlerter{}, &recordingAlerter{}
		r := PolicyRouter{Resolve: policyOf(pol), Channels: map[string]Alerter{"pagerduty": pd, "slack": slack}, Default: def}
		_ = r.IncidentOpened(context.Background(), platform.Incident{TenantID: "t1", Severity: "critical"})
		if atomic.LoadInt32(&pd.fired) != 1 || atomic.LoadInt32(&slack.fired) != 1 {
			t.Errorf("critical should hit pagerduty+slack, got pd=%d slack=%d", pd.fired, slack.fired)
		}
		if atomic.LoadInt32(&def.fired) != 0 {
			t.Error("default must NOT fire when the policy matched")
		}
	})

	t.Run("high → slack only", func(t *testing.T) {
		pd, slack, def := &recordingAlerter{}, &recordingAlerter{}, &recordingAlerter{}
		r := PolicyRouter{Resolve: policyOf(pol), Channels: map[string]Alerter{"pagerduty": pd, "slack": slack}, Default: def}
		_ = r.IncidentOpened(context.Background(), platform.Incident{TenantID: "t1", Severity: "high"})
		if atomic.LoadInt32(&slack.fired) != 1 || atomic.LoadInt32(&pd.fired) != 0 {
			t.Errorf("high should hit slack only, got pd=%d slack=%d", pd.fired, slack.fired)
		}
	})
}

// No policy / disabled / below floor → fall back to Default (today's alert-all behaviour).
func TestPolicyRouter_FallsBackWhenNoMatch(t *testing.T) {
	def := &recordingAlerter{}
	r := PolicyRouter{Resolve: policyOf(nil), Channels: map[string]Alerter{"slack": &recordingAlerter{}}, Default: def}
	_ = r.IncidentOpened(context.Background(), platform.Incident{TenantID: "t1", Severity: "critical"})
	if atomic.LoadInt32(&def.fired) != 1 {
		t.Error("with no policy, the default alerter must fire")
	}
}

// A policy that matches but names only channels the operator hasn't configured must NOT silently
// drop the alert — it falls back to Default so the incident is never lost.
func TestPolicyRouter_UnconfiguredChannelFallsBack(t *testing.T) {
	pol := &platform.EscalationPolicy{Enabled: true, Tiers: []platform.EscalationTier{
		{MinSeverity: "low", Channels: []string{"teams"}}, // teams not in the map
	}}
	def := &recordingAlerter{}
	r := PolicyRouter{Resolve: policyOf(pol), Channels: map[string]Alerter{"slack": &recordingAlerter{}}, Default: def}
	_ = r.IncidentOpened(context.Background(), platform.Incident{TenantID: "t1", Severity: "critical"})
	if atomic.LoadInt32(&def.fired) != 1 {
		t.Error("a policy naming only unconfigured channels must fall back to default, not drop the alert")
	}
}
