package ciem

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

func findFor(fs []Finding, principal string) *Finding {
	for i := range fs {
		if fs[i].Principal == principal {
			return &fs[i]
		}
	}
	return nil
}

// TestRightsize_DormantAdmin: a privileged principal granted iam:* that used nothing is the prime CIEM
// finding — high severity, the whole grant flagged unused.
func TestRightsize_DormantAdmin(t *testing.T) {
	grants := []Grant{{Principal: "deploy-role", Privileged: true, Actions: []string{"iam:*", "s3:GetObject"}}}
	usage := map[string]Usage{"deploy-role": {Observed: true, WindowDays: 90, Actions: nil}}
	fs := Rightsize(grants, usage)
	f := findFor(fs, "deploy-role")
	if f == nil {
		t.Fatal("a dormant privileged role must be flagged")
	}
	if f.Severity != "high" {
		t.Errorf("dormant admin must be high severity, got %s", f.Severity)
	}
	if len(f.UnusedActions) != 2 {
		t.Errorf("both granted actions are unused, got %v", f.UnusedActions)
	}
	if !strings.Contains(f.Recommendation, "least privilege") {
		t.Errorf("recommendation should state least privilege: %q", f.Recommendation)
	}
}

// TestRightsize_OverbroadWildcard: s3:* used only for s3:GetObject → a narrowing hint, not a full removal.
func TestRightsize_OverbroadWildcard(t *testing.T) {
	grants := []Grant{{Principal: "app", Actions: []string{"s3:*"}}}
	usage := map[string]Usage{"app": {Observed: true, WindowDays: 30, Actions: []string{"s3:GetObject", "s3:ListBucket"}}}
	fs := Rightsize(grants, usage)
	f := findFor(fs, "app")
	if f == nil {
		t.Fatal("an over-broad-but-used wildcard should still be reported for narrowing")
	}
	if len(f.UnusedActions) != 0 {
		t.Errorf("s3:* was used, so it is not fully unused: %v", f.UnusedActions)
	}
	if len(f.OverbroadHints) != 1 || !strings.Contains(f.OverbroadHints[0], "s3:GetObject") {
		t.Errorf("expected a narrowing hint naming the used subset, got %v", f.OverbroadHints)
	}
}

// TestRightsize_FullyUsed_NoFinding: a principal that used everything it was granted is right-sized.
func TestRightsize_FullyUsed_NoFinding(t *testing.T) {
	grants := []Grant{{Principal: "tight", Actions: []string{"s3:GetObject", "sqs:SendMessage"}}}
	usage := map[string]Usage{"tight": {Observed: true, WindowDays: 90, Actions: []string{"s3:GetObject", "sqs:SendMessage"}}}
	if fs := Rightsize(grants, usage); len(fs) != 0 {
		t.Errorf("a fully-used principal must produce no finding, got %v", fs)
	}
}

// TestRightsize_NoUsageData_Skipped is the honest gate (§10): without observed usage we make NO claim —
// absence of logs is not evidence of non-use.
func TestRightsize_NoUsageData_Skipped(t *testing.T) {
	grants := []Grant{{Principal: "unknown", Privileged: true, Actions: []string{"iam:*"}}}
	// no entry at all
	if fs := Rightsize(grants, map[string]Usage{}); len(fs) != 0 {
		t.Errorf("no usage data → no finding, got %v", fs)
	}
	// present but Observed=false → still skipped
	if fs := Rightsize(grants, map[string]Usage{"unknown": {Observed: false}}); len(fs) != 0 {
		t.Errorf("Observed=false → no finding, got %v", fs)
	}
}

// TestRightsize_SeverityOrder: high-severity findings sort before medium.
func TestRightsize_SeverityOrder(t *testing.T) {
	grants := []Grant{
		{Principal: "low-risk", Actions: []string{"sqs:ReceiveMessage", "sqs:DeleteMessage"}},
		{Principal: "admin", Privileged: true, Actions: []string{"iam:CreateAccessKey"}},
	}
	usage := map[string]Usage{
		"low-risk": {Observed: true, WindowDays: 30, Actions: []string{"sqs:ReceiveMessage"}},
		"admin":    {Observed: true, WindowDays: 30, Actions: nil},
	}
	fs := Rightsize(grants, usage)
	if len(fs) != 2 || fs[0].Principal != "admin" || fs[0].Severity != "high" {
		t.Errorf("high-severity dormant admin must sort first, got %+v", fs)
	}
}

// TestGrantFromDocuments extracts Allow actions and treats NotAction-Allow as a maximally-broad grant.
func TestGrantFromDocuments(t *testing.T) {
	allow, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`))
	g := GrantFromDocuments("p", false, []*cloudiam.Document{allow})
	if len(g.Actions) != 2 {
		t.Errorf("only the 2 Allow actions are granted (Deny ignored), got %v", g.Actions)
	}
	notAction, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`))
	g2 := GrantFromDocuments("p2", true, []*cloudiam.Document{notAction})
	if len(g2.Actions) != 1 || g2.Actions[0] != "*" {
		t.Errorf("a NotAction-Allow must be treated as a '*' broad grant, got %v", g2.Actions)
	}
}
