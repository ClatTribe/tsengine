package cloudiam

import "testing"

// TestDetectPrivesc_RolePolicyNeedsBothPerms: AttachRolePolicy / PutRolePolicy / UpdateAssumeRolePolicy
// each require BOTH the iam write action AND sts:AssumeRole (modify a role's policy, then assume the role
// to use it — the PMapper/Rhino model). They were encoded as a single OR-group, so EITHER permission
// alone fired them. sts:AssumeRole alone — which nearly every principal holds for some role — would then
// trip all three, a false-positive privesc edge that breaks the no-FP bar (§10).
func TestDetectPrivesc_RolePolicyNeedsBothPerms(t *testing.T) {
	both := map[string]bool{"AttachRolePolicy": true, "PutRolePolicy": true, "UpdateAssumeRolePolicy": true}

	// sts:AssumeRole ALONE must fire none of them.
	assumeOnly := map[string]bool{"sts:AssumeRole": true}
	for _, tech := range DetectPrivesc(func(a string) bool { return assumeOnly[a] }) {
		if both[tech.Name] {
			t.Errorf("%q must NOT fire with sts:AssumeRole alone (it also needs the iam write perm)", tech.Name)
		}
	}

	// The iam write perm ALONE must also fire none of them.
	for _, iamPerm := range []string{"iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"} {
		only := map[string]bool{iamPerm: true}
		for _, tech := range DetectPrivesc(func(a string) bool { return only[a] }) {
			if both[tech.Name] {
				t.Errorf("%q must NOT fire with %s alone (it also needs sts:AssumeRole to use the role)", tech.Name, iamPerm)
			}
		}
	}

	// BOTH perms together DO fire the technique.
	for _, pair := range []struct{ name, iamPerm string }{
		{"AttachRolePolicy", "iam:AttachRolePolicy"},
		{"PutRolePolicy", "iam:PutRolePolicy"},
		{"UpdateAssumeRolePolicy", "iam:UpdateAssumeRolePolicy"},
	} {
		set := map[string]bool{pair.iamPerm: true, "sts:AssumeRole": true}
		fired := false
		for _, tech := range DetectPrivesc(func(a string) bool { return set[a] }) {
			if tech.Name == pair.name {
				fired = true
			}
		}
		if !fired {
			t.Errorf("%q must fire with both %s and sts:AssumeRole", pair.name, pair.iamPerm)
		}
	}
}
