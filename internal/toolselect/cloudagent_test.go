package toolselect

import (
	"context"
	"testing"
)

// cloudCatalog models the REAL AI-Security-Engineer library (internal/cloudagent/tools.go, 11 tools)
// with an explore→chain→remediate phase model. It proves toolselect works for the SECOND flagship
// agent, not just the offensive one — task-driven retrieval + phase-scoping over the cloud graph tools.
func cloudCatalog() *Catalog {
	return NewCatalog([]Tool{
		{Name: "list_resources", Description: "inventory of cloud resources and principals", AlwaysOn: true},
		{Name: "record_issue", Description: "commit a real attack path that ends at a crown jewel", AlwaysOn: true},
		{Name: "finish", Description: "end the investigation with an executive summary", AlwaysOn: true},
		{Name: "get_resource", Description: "one resource's metadata and outgoing edges", Tags: []string{"resource", "metadata", "edges"}, Phases: []string{"explore"}},
		{Name: "get_findings", Description: "prowler config-bad findings to triage", Tags: []string{"prowler", "config", "findings", "triage"}, Phases: []string{"explore"}},
		{Name: "resolve_access", Description: "does a principal have an effective iam path to a resource", Tags: []string{"iam", "access", "authz", "reachability", "permission"}, Phases: []string{"chain"}},
		{Name: "find_paths", Description: "concrete attack paths from the internet to a target node", Tags: []string{"attack", "path", "internet", "exposure", "reach"}, Phases: []string{"chain"}},
		{Name: "blast_radius", Description: "every crown jewel reachable if a principal is compromised", Tags: []string{"blast", "radius", "crown", "jewel", "compromise", "lateral"}, Phases: []string{"chain"}},
		{Name: "detect_privesc", Description: "known iam privilege escalation moves available to a principal", Tags: []string{"privesc", "privilege", "escalation", "iam", "admin"}, Phases: []string{"chain"}},
		{Name: "enumerate_attack_paths", Description: "deterministic candidate attack paths as a prepass seed", Tags: []string{"attack", "paths", "enumerate", "prepass"}, Phases: []string{"explore", "chain"}},
		{Name: "propose_fix", Description: "generate an iam-verified remediation that cuts the recorded issue's edge", Tags: []string{"fix", "remediation", "iam", "cut"}, Phases: []string{"remediate"}},
	})
}

func TestSelect_CloudEngineer_TaskAndPhase(t *testing.T) {
	cat := cloudCatalog()
	order := []string{"explore", "chain", "remediate"}

	// Chain phase, privesc task → the privesc/reachability tools surface; the remediation tool does not.
	sel := cat.Select(Query{
		Task:  "which principals can escalate their privilege to admin and reach the crown jewels",
		Phase: "chain", PhaseOrder: order, MaxActive: 8,
	})
	names := sel.Names()
	for _, w := range []string{"detect_privesc", "blast_radius"} {
		if !contains(names, w) {
			t.Errorf("chain/privesc task should surface %q, got %v", w, names)
		}
	}
	if contains(names, "propose_fix") {
		t.Errorf("propose_fix is a remediate-phase tool; must be hidden in chain, got %v", names)
	}
	// CORE always present.
	for _, core := range []string{"list_resources", "record_issue", "finish"} {
		if !contains(names, core) {
			t.Errorf("core tool %q must be present, got %v", core, names)
		}
	}

	// Remediate phase, fix task → propose_fix becomes eligible (later phase keeps earlier caps too).
	sel2 := cat.Select(Query{Task: "generate a fix that cuts the privilege-escalation edge", Phase: "remediate", PhaseOrder: order, MaxActive: 8})
	if !contains(sel2.Names(), "propose_fix") {
		t.Errorf("remediate-phase fix task should surface propose_fix, got %v", sel2.Names())
	}
}

func TestSelectLLM_CloudEngineer_FrontierProxy(t *testing.T) {
	cat := cloudCatalog()
	// Semantic task: "a build robot can rewrite its own permissions" describes IAM privilege escalation,
	// but shares no token with detect_privesc's tags. Frontier model (via claude-as-proxy) picks it.
	task := "a build robot account can rewrite its own permissions to become all-powerful"
	sel, fb := cat.SelectLLM(context.Background(), Query{Task: task, MaxActive: 7}, &mockGen{resp: `["detect_privesc","resolve_access"]`})
	if fb {
		t.Fatal("valid frontier answer should not fall back")
	}
	if !contains(sel.Names(), "detect_privesc") {
		t.Fatalf("frontier refiner should surface detect_privesc for a described self-privilege-rewrite, got %v", sel.Names())
	}
}
