package clouddrift

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func baseline() *cloudgraph.Snapshot {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork})
	s.AddNode(&cloudgraph.Node{ID: "bucket-1", Kind: cloudgraph.KindResource, Name: "data-bucket", Type: "AWS::S3::Bucket", Public: false, Sensitive: cloudgraph.SensHigh})
	s.AddNode(&cloudgraph.Node{ID: "role-app", Kind: cloudgraph.KindPrincipal, Name: "app-role", Privileged: false})
	return s
}

func ruleSet(fs []interface{ GetRuleID() string }) {} // placeholder; not used

func TestDiff_DetectsConfigDrift(t *testing.T) {
	prev := baseline()

	cur := baseline()
	cur.Nodes["bucket-1"].Public = true                                 // became public
	cur.Nodes["role-app"].Privileged = true                             // escalated to privileged
	cur.AddNode(&cloudgraph.Node{ID: "role-new", Kind: cloudgraph.KindPrincipal, Name: "new-admin", Privileged: true}) // new privileged principal
	cur.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: "bucket-1", Kind: cloudgraph.EdgeNetworkReach})        // new internet exposure
	cur.AddEdge(cloudgraph.Edge{From: "role-app", To: "admin", Kind: cloudgraph.EdgePrivesc, Detail: "AttachRolePolicy"}) // new privesc

	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	got := map[string]bool{}
	for _, f := range Diff(prev, cur, Options{Now: now}) {
		got[f.RuleID] = true
		if f.Compliance == nil || len(f.Compliance.SOC2) == 0 {
			t.Errorf("%s missing change-control compliance", f.RuleID)
		}
	}
	for _, want := range []string{
		"clouddrift::resource-became-public", "clouddrift::principal-became-privileged",
		"clouddrift::new-privileged-principal", "clouddrift::new-internet-exposure",
		"clouddrift::new-privilege-escalation",
	} {
		if !got[want] {
			t.Errorf("expected drift finding %q", want)
		}
	}
}

// An unchanged snapshot pair yields ZERO findings (drift is not noise) — and a nil baseline (first
// observation) also yields nothing (a first scan isn't drift).
func TestDiff_NoChangeNoFindings(t *testing.T) {
	if f := Diff(baseline(), baseline(), Options{}); len(f) != 0 {
		t.Errorf("identical snapshots must yield zero drift, got %d: %+v", len(f), f)
	}
	if f := Diff(nil, baseline(), Options{}); len(f) != 0 {
		t.Errorf("a first observation (nil baseline) is not drift, got %d", len(f))
	}
}
