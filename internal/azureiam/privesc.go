package azureiam

// Known Azure (ARM-plane) privilege-escalation techniques. Each technique is a set of RBAC actions that,
// together, let a principal escalate to higher privilege. If a principal's effective permissions cover
// every group (one action per group), it can escalate → a `privesc` edge in the graph. This is the Azure
// twin of internal/cloudiam.Techniques (AWS) and internal/gcpiam.Techniques (GCP) — so multi-cloud
// attack-path reasoning is symmetric across all three clouds, not shallower on Azure (CLAUDE.md §10).
//
// Scope: the ARM control plane (Microsoft.* actions), matching azureiam.Authorize. The Azure AD / Entra
// graph plane (app-credential add, owner-of-privileged-SP, privileged directory-role assignment) is a
// DISTINCT authorization plane — its privesc catalog lives in entra_privesc.go (EntraTechniques /
// DetectEntraPrivesc), wired into the graph by cloudgraph.AddAzureEntraPrivescEdges, and is NOT folded in
// here (we don't conflate the two planes, §10). Together the two catalogs cover Azure privesc across both
// planes.
//
// This is the documented, finite set of Azure RBAC privesc primitives mapped to a graph edge (CLAUDE.md
// §13 — derivation logic, not a new in-house scanner).

// Technique is one privesc method: every group in All must be satisfied (the principal can do at least one
// action in each group).
type Technique struct {
	Name string
	All  [][]string // AND of (OR of actions)
}

// Techniques is the Azure ARM privesc catalog. Actions are case-insensitive (the injected `can` —
// typically wrapping azureiam.Authorize — lowercases), in canonical Microsoft.* form here.
var Techniques = []Technique{
	// Grant yourself (or a controlled principal) a role at any scope — the most direct escalation (Owner /
	// User Access Administrator hold this).
	{Name: "RoleAssignmentWrite", All: [][]string{{"Microsoft.Authorization/roleAssignments/write"}}},
	// Global Admin elevates to User Access Administrator at the root (/) scope, then assigns roles tenant-wide.
	{Name: "ElevateAccess", All: [][]string{{"Microsoft.Authorization/elevateAccess/action"}}},
	// Edit a custom role definition you are assigned to add permissions to yourself.
	{Name: "RoleDefinitionWrite", All: [][]string{{"Microsoft.Authorization/roleDefinitions/write"}}},
	// Run a command on a VM — it executes as the VM's (potentially privileged) managed identity.
	{Name: "VMRunCommand", All: [][]string{{"Microsoft.Compute/virtualMachines/runCommand/action"}}},
	// Deploy a custom-script extension that executes as the VM's managed identity.
	{Name: "VMExtensionWrite", All: [][]string{{"Microsoft.Compute/virtualMachines/extensions/write"}}},
	// Create/modify an automation runbook — it runs as the automation account's privileged Run-As / MI.
	{Name: "AutomationRunbookWrite", All: [][]string{{"Microsoft.Automation/automationAccounts/runbooks/write", "Microsoft.Automation/automationAccounts/runbooks/draft/write"}}},
	// Deploy/modify a Function/Web app — its code executes as the app's managed identity.
	{Name: "FunctionAppWrite", All: [][]string{{"Microsoft.Web/sites/write"}, {"Microsoft.Web/sites/functions/write", "Microsoft.Web/sites/host/listkeys/action"}}},
	// Grant yourself a Key Vault access policy → read its secrets/keys (credential harvesting).
	{Name: "KeyVaultAccessPolicyWrite", All: [][]string{{"Microsoft.KeyVault/vaults/accessPolicies/write"}}},
}

// DetectPrivesc returns the Azure privesc techniques a principal's effective permissions enable. `can`
// answers whether an action is held — typically wrapping azureiam.Authorize over the principal's
// hierarchy-inherited role assignments, so callers get policy-accurate escalation detection.
func DetectPrivesc(can func(action string) bool) []Technique {
	if can == nil {
		return nil
	}
	var out []Technique
	for _, t := range Techniques {
		if satisfies(t, can) {
			out = append(out, t)
		}
	}
	return out
}

func satisfies(t Technique, can func(string) bool) bool {
	for _, group := range t.All {
		anyOK := false
		for _, a := range group {
			if can(a) {
				anyOK = true
				break
			}
		}
		if !anyOK {
			return false
		}
	}
	return true
}
