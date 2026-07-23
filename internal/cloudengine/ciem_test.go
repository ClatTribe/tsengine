package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func principal(id string, priv bool, attrs map[string]string) *cloudgraph.Node {
	return &cloudgraph.Node{ID: id, Kind: cloudgraph.KindPrincipal, Privileged: priv, Attrs: attrs}
}

// TestRightsizePrincipals_DormantAdmin: a privileged principal granted iam:* that used nothing (observed)
// yields a high CIEM finding with the least-privilege compliance crosswalk.
func TestRightsizePrincipals_DormantAdmin(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(principal("deploy-role", true, map[string]string{
		attrGrantedActions:  "iam:* s3:GetObject",
		attrUsedActions:     "",
		attrUsageObserved:   "true",
		attrUsageWindowDays: "90",
	}))
	fs := RightsizePrincipals(s)
	if len(fs) != 1 {
		t.Fatalf("want 1 CIEM finding, got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "ciem::over-privileged-principal" || f.Tool != "ciem" {
		t.Errorf("wrong rule/tool: %s / %s", f.RuleID, f.Tool)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("dormant admin must be high, got %s", f.Severity)
	}
	if f.Endpoint != "deploy-role" {
		t.Errorf("endpoint should be the principal, got %s", f.Endpoint)
	}
	if f.Compliance == nil || len(f.Compliance.NIST80053) == 0 {
		t.Error("CIEM finding must carry the least-privilege compliance crosswalk (NIST AC-6)")
	}
}

// TestRightsizePrincipals_HonestGate: a principal with granted actions but NO observed usage yields no
// finding — absence of usage data is not evidence of non-use (§10).
func TestRightsizePrincipals_HonestGate(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(principal("p", true, map[string]string{attrGrantedActions: "iam:*"})) // no usage_observed
	if fs := RightsizePrincipals(s); len(fs) != 0 {
		t.Errorf("no usage data → no CIEM finding, got %d", len(fs))
	}
}

// TestRightsizePrincipals_FullyUsedAndNil: a fully-used principal yields nothing; nil snapshot → nil.
func TestRightsizePrincipals_FullyUsedAndNil(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(principal("tight", false, map[string]string{
		attrGrantedActions: "s3:GetObject sqs:SendMessage",
		attrUsedActions:    "s3:GetObject sqs:SendMessage",
		attrUsageObserved:  "true",
	}))
	if fs := RightsizePrincipals(s); len(fs) != 0 {
		t.Errorf("a fully-used principal must produce no finding, got %d", len(fs))
	}
	if RightsizePrincipals(nil) != nil {
		t.Error("nil snapshot → nil")
	}
}
