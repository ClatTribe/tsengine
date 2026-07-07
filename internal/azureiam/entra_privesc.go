package azureiam

import "strings"

// Entra (Azure AD) GRAPH-plane privilege-escalation techniques — the DISTINCT identity-plane twin of the
// ARM-plane Techniques (privesc.go). This closes the documented multi-cloud gap (CLAUDE.md §10): ARM
// privesc was symmetric across AWS+GCP+Azure, but Azure has a SECOND authorization plane — Entra ID — whose
// privesc primitives (add a credential to a privileged app, assign yourself a directory role, own a
// privileged service principal) are invisible to the ARM `Microsoft.*` catalog. An attacker who can add a
// secret to an app that holds `RoleManagement.ReadWrite.Directory` becomes Global Admin without ever
// touching an ARM role assignment.
//
// The plane is kept SEPARATE from ARM (§10 — we don't conflate the two authorization planes): the `can`
// predicate here answers whether a principal effectively holds a MICROSOFT GRAPH application permission OR
// a privileged DIRECTORY ROLE, not an ARM action. The ingest builds it from the Entra snapshot's app-role
// assignments + directory-role memberships + app ownerships (the honest gate — same as the ARM side).
//
// Tokens are canonical Graph permission values (e.g. "Application.ReadWrite.All") and directory-role
// display names (e.g. "Application Administrator"); `can` is expected to answer both (the ingest
// normalizes). Sources: Microsoft Entra role docs + the BloodHound/AzureHound Entra edge catalog
// (AddSecret, AddOwner, AppRoleAssignment_ReadWrite_All, GrantAppRoles). Derivation logic mapped to a
// graph edge — NOT a new in-house scanner (§13).
var EntraTechniques = []Technique{
	// Assign yourself (or a controlled principal) ANY directory role, including Global Administrator — the
	// graph-plane equivalent of ARM ElevateAccess. The single strongest Entra escalation.
	{Name: "Entra:RoleManagementWrite", All: [][]string{{"RoleManagement.ReadWrite.Directory"}}},
	// Privileged Role Administrator can manage role assignments (grant self any role).
	{Name: "Entra:PrivilegedRoleAdmin", All: [][]string{{"Privileged Role Administrator"}}},
	// Add a credential (password/key) to ANY app registration or service principal, then authenticate AS it
	// — inheriting whatever (possibly Global-Admin-equivalent) app roles that SP holds.
	{Name: "Entra:AppCredentialWriteAny", All: [][]string{{"Application.ReadWrite.All", "Directory.ReadWrite.All"}}},
	// Application / Cloud Application Administrator can add credentials to existing service principals (the
	// directory-role path to the same AddSecret escalation).
	{Name: "Entra:ApplicationAdminRole", All: [][]string{{"Application Administrator", "Cloud Application Administrator"}}},
	// Grant an app (that you control) a high-privilege app role — e.g. give it RoleManagement.ReadWrite.
	// Directory — via the app-role-assignment permission.
	{Name: "Entra:AppRoleAssignmentWrite", All: [][]string{{"AppRoleAssignment.ReadWrite.All"}}},
	// Add yourself to a ROLE-ASSIGNABLE group → inherit its directory roles.
	{Name: "Entra:GroupMemberWrite", All: [][]string{{"GroupMember.ReadWrite.All", "Group.ReadWrite.All"}}},
	// Reset a privileged user's (e.g. a Global Admin's) authentication method / password → take over the
	// account. Privileged Authentication Administrator is the role that can target admins.
	{Name: "Entra:AuthMethodWrite", All: [][]string{{"UserAuthenticationMethod.ReadWrite.All", "Privileged Authentication Administrator"}}},
}

// DetectEntraPrivesc returns the Entra graph-plane privesc techniques a principal's effective Graph
// permissions / directory roles enable. `can` answers whether the principal effectively holds a given
// Graph permission OR directory role (the ingest builds it from the Entra snapshot). nil `can` → nil.
// Mirrors DetectPrivesc for the ARM plane, so the two planes are detected symmetrically without being
// conflated.
func DetectEntraPrivesc(can func(perm string) bool) []Technique {
	if can == nil {
		return nil
	}
	var out []Technique
	for _, t := range EntraTechniques {
		if satisfies(t, can) {
			out = append(out, t)
		}
	}
	return out
}

// EntraCanFromGrants builds a `can` predicate from a principal's concrete Entra holdings — the Graph
// application permissions granted to it plus the directory roles it holds. Case-insensitive match on
// either list, so the ingest can pass raw snapshot values. A convenience for callers that have the two
// lists already (the honest gate stays the ingest's: it must actually collect them).
func EntraCanFromGrants(graphPermissions, directoryRoles []string) func(string) bool {
	held := make(map[string]bool, len(graphPermissions)+len(directoryRoles))
	for _, p := range graphPermissions {
		held[strings.ToLower(strings.TrimSpace(p))] = true
	}
	for _, r := range directoryRoles {
		held[strings.ToLower(strings.TrimSpace(r))] = true
	}
	return func(token string) bool { return held[strings.ToLower(strings.TrimSpace(token))] }
}
