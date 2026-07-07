package azureiam

import (
	"sort"
	"strings"
	"testing"
)

// techNames returns the detected technique names, sorted, for stable assertions.
func techNames(ts []Technique) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	sort.Strings(out)
	return out
}

func has(ts []Technique, name string) bool {
	for _, t := range ts {
		if t.Name == name {
			return true
		}
	}
	return false
}

// TestDetectEntraPrivesc_GraphPermissionsAndRoles: each Entra graph-plane primitive is detected from the
// principal's effective Graph permission OR privileged directory role — the DISTINCT identity-plane twin of
// the ARM catalog. A benign principal (read-only Graph scope) escalates via NONE.
func TestDetectEntraPrivesc_GraphPermissionsAndRoles(t *testing.T) {
	cases := []struct {
		name  string
		holds []string
		want  string // the technique that must fire
	}{
		{"role-management write → global admin", []string{"RoleManagement.ReadWrite.Directory"}, "Entra:RoleManagementWrite"},
		{"app credential write (any app secret)", []string{"Application.ReadWrite.All"}, "Entra:AppCredentialWriteAny"},
		{"directory write (broad)", []string{"Directory.ReadWrite.All"}, "Entra:AppCredentialWriteAny"},
		{"application administrator role", []string{"Application Administrator"}, "Entra:ApplicationAdminRole"},
		{"app-role assignment write", []string{"AppRoleAssignment.ReadWrite.All"}, "Entra:AppRoleAssignmentWrite"},
		{"role-assignable group membership", []string{"GroupMember.ReadWrite.All"}, "Entra:GroupMemberWrite"},
		{"privileged auth admin resets GA", []string{"Privileged Authentication Administrator"}, "Entra:AuthMethodWrite"},
		{"privileged role admin", []string{"Privileged Role Administrator"}, "Entra:PrivilegedRoleAdmin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			can := EntraCanFromGrants(c.holds, nil)
			got := DetectEntraPrivesc(can)
			if !has(got, c.want) {
				t.Errorf("holds %v should enable %q, got %v", c.holds, c.want, techNames(got))
			}
		})
	}

	// a benign principal — only a READ scope — escalates via nothing.
	benign := EntraCanFromGrants([]string{"User.Read.All", "Directory.Read.All"}, nil)
	if got := DetectEntraPrivesc(benign); len(got) != 0 {
		t.Errorf("a read-only principal must have NO Entra privesc, got %v", techNames(got))
	}

	// nil predicate → nil (no crash).
	if DetectEntraPrivesc(nil) != nil {
		t.Error("nil can → nil")
	}
}

// TestEntraCanFromGrants_CaseInsensitive: the ingest can pass raw snapshot values (any case / whitespace)
// and the predicate still matches — grounded on the real holding, tolerant of source formatting.
func TestEntraCanFromGrants_CaseInsensitive(t *testing.T) {
	can := EntraCanFromGrants([]string{"  application.readwrite.all  "}, []string{"APPLICATION ADMINISTRATOR"})
	if !can("Application.ReadWrite.All") {
		t.Error("permission match must be case/space-insensitive")
	}
	if !can("Application Administrator") {
		t.Error("directory-role match must be case-insensitive")
	}
	if can("RoleManagement.ReadWrite.Directory") {
		t.Error("a permission the principal does NOT hold must not match")
	}
	// the directory-role holding drives the ApplicationAdminRole escalation.
	if !has(DetectEntraPrivesc(can), "Entra:ApplicationAdminRole") {
		t.Error("holding Application Administrator must enable Entra:ApplicationAdminRole")
	}
}

// TestEntraTechniques_DistinctFromARM: the Entra catalog is a SEPARATE plane — its tokens are Graph
// permissions / directory roles, never ARM Microsoft.* actions (§10, planes not conflated).
func TestEntraTechniques_DistinctFromARM(t *testing.T) {
	for _, tech := range EntraTechniques {
		for _, group := range tech.All {
			for _, tok := range group {
				if strings.HasPrefix(strings.ToLower(tok), "microsoft.") {
					t.Errorf("Entra technique %q uses an ARM action %q — the two planes must not be conflated", tech.Name, tok)
				}
			}
		}
	}
	// and an ARM privesc holder does NOT trip an Entra technique (different plane).
	armOnly := EntraCanFromGrants([]string{"Microsoft.Authorization/roleAssignments/write"}, nil)
	if got := DetectEntraPrivesc(armOnly); len(got) != 0 {
		t.Errorf("an ARM-only permission must not enable an Entra technique, got %v", techNames(got))
	}
}
