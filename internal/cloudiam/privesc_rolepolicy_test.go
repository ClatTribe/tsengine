package cloudiam

import "testing"

// THE FALSE POSITIVE THIS GUARDS IS STILL GUARDED. These three techniques were once
// encoded as a single OR-group, so EITHER permission alone fired them — and sts:AssumeRole
// alone, which nearly every principal holds for some role, tripped all three. That was a
// mass false-positive privesc edge and the no-FP bar (§10) exists to stop it.
//
// WHAT CHANGED, AND WHY. The fix at the time was to require BOTH permissions. That killed
// the FP, but it also meant iam:AttachRolePolicy alone — a principal who can attach
// AdministratorAccess to a role — reported NOTHING. The IAM-Vulnerable corpus (BishopFox)
// names both writes as escalation paths granting only the write, and Rhino's original
// research does the same; scoring against that external key is how we found we had quietly
// disagreed with the published catalogues.
//
// So the requirement is now the WRITE alone, and the precondition ("you must be able to
// use the role afterwards") moved to Technique.Note where a reader can weigh it. The FP
// guard is untouched by that: sts:AssumeRole is no longer part of the requirement at all,
// so holding it alone still fires nothing.
//
// UpdateAssumeRolePolicy deliberately KEEPS both, because rewriting a trust policy to let
// yourself assume the role is the complete path — there is no precondition left to state.
func TestDetectPrivesc_RolePolicyTechniques(t *testing.T) {
	both := map[string]bool{"AttachRolePolicy": true, "PutRolePolicy": true, "UpdateAssumeRolePolicy": true}

	// THE ORIGINAL BUG, still guarded: sts:AssumeRole ALONE must fire none of them.
	assumeOnly := map[string]bool{"sts:AssumeRole": true}
	for _, tech := range DetectPrivesc(func(a string) bool { return assumeOnly[a] }) {
		if both[tech.Name] {
			t.Errorf("%q must NOT fire with sts:AssumeRole alone — nearly every principal holds it, "+
				"and that was a mass false positive", tech.Name)
		}
	}

	// The two WRITE techniques now fire on the write alone, and must carry the caveat.
	for name, perm := range map[string]string{
		"AttachRolePolicy": "iam:AttachRolePolicy",
		"PutRolePolicy":    "iam:PutRolePolicy",
	} {
		only := map[string]bool{perm: true}
		var got *Technique
		for _, tech := range DetectPrivesc(func(a string) bool { return only[a] }) {
			if tech.Name == name {
				t := tech
				got = &t
			}
		}
		if got == nil {
			t.Errorf("%q must fire with %s alone — attaching AdministratorAccess to a role is an "+
				"escalation primitive, and both BishopFox and Rhino name it as one", name, perm)
			continue
		}
		if got.Note == "" {
			t.Errorf("%q fires on the write alone, so the precondition MUST be stated in Note — "+
				"otherwise we are silently claiming more than the permissions prove", name)
		}
	}

	// UpdateAssumeRolePolicy still needs both: the write alone must fire nothing.
	uarOnly := map[string]bool{"iam:UpdateAssumeRolePolicy": true}
	for _, tech := range DetectPrivesc(func(a string) bool { return uarOnly[a] }) {
		if tech.Name == "UpdateAssumeRolePolicy" {
			t.Error("UpdateAssumeRolePolicy still requires sts:AssumeRole — rewriting the trust policy " +
				"and then assuming the role is the whole path, with no precondition left to state")
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
