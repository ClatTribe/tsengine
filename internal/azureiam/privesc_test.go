package azureiam

import "testing"

func TestDetectPrivesc_Azure(t *testing.T) {
	fire := func(perms ...string) map[string]bool {
		m := map[string]bool{}
		for _, p := range perms {
			m[p] = true
		}
		return m
	}
	cases := map[string][]string{
		"RoleAssignmentWrite":       {"Microsoft.Authorization/roleAssignments/write"},
		"ElevateAccess":             {"Microsoft.Authorization/elevateAccess/action"},
		"RoleDefinitionWrite":       {"Microsoft.Authorization/roleDefinitions/write"},
		"VMRunCommand":              {"Microsoft.Compute/virtualMachines/runCommand/action"},
		"VMExtensionWrite":          {"Microsoft.Compute/virtualMachines/extensions/write"},
		"AutomationRunbookWrite":    {"Microsoft.Automation/automationAccounts/runbooks/write"},
		"KeyVaultAccessPolicyWrite": {"Microsoft.KeyVault/vaults/accessPolicies/write"},
	}
	for want, perms := range cases {
		set := fire(perms...)
		got := false
		for _, tech := range DetectPrivesc(func(a string) bool { return set[a] }) {
			if tech.Name == want {
				got = true
			}
		}
		if !got {
			t.Errorf("expected Azure privesc technique %q for actions %v", want, perms)
		}
	}
	// FunctionAppWrite needs BOTH a site write AND a function/key action (AND contract) — site/write alone is not enough.
	siteOnly := fire("Microsoft.Web/sites/write")
	for _, tech := range DetectPrivesc(func(a string) bool { return siteOnly[a] }) {
		if tech.Name == "FunctionAppWrite" {
			t.Error("FunctionAppWrite must not fire on Microsoft.Web/sites/write alone (needs the function/key action)")
		}
	}
	full := fire("Microsoft.Web/sites/write", "Microsoft.Web/sites/host/listkeys/action")
	ok := false
	for _, tech := range DetectPrivesc(func(a string) bool { return full[a] }) {
		if tech.Name == "FunctionAppWrite" {
			ok = true
		}
	}
	if !ok {
		t.Error("FunctionAppWrite should fire with sites/write + host/listkeys/action")
	}
	// a reader escalates to nothing.
	if got := DetectPrivesc(func(string) bool { return false }); len(got) != 0 {
		t.Errorf("a principal with no privesc actions must yield zero techniques, got %v", got)
	}
}
