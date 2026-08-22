package gcpinventory

import "testing"

// THE FALSE-POSITIVE CONTROL BishopFox's AWS set asks of every tool: "Does the tool evaluate deny's
// first before allows? Many tools ignore or incorrectly handle DENY actions."
//
// GCP evaluates IAM deny BEFORE allow, and a deny on resourcemanager.projects.setIamPolicy is the
// documented guardrail a customer puts in place against exactly this escalation. gcpiam.Authorize
// has always honoured denies — but RawGCP could not EXPRESS one, so derivePrivesc built its
// PolicySet without any and reported a path to administrator against the customers who had taken
// the strongest available precaution.
//
// This is the specificity half the GCP row has never had. It can go DOWN when detections are added,
// which is the point of it.
func TestDerivePrivesc_AnIAMDenyBlocksTheEscalation(t *testing.T) {
	const member = "user:eve@corp.example"
	base := RawGCP{
		ProjectID: "p1",
		Members:   []RawGCPMember{{Member: member}},
		Bindings: []RawGCPBinding{{
			Role: "roles/resourcemanager.projectIamAdmin", Members: []string{member},
		}},
		RoleDefs: map[string][]string{
			"roles/resourcemanager.projectIamAdmin": {"resourcemanager.projects.setIamPolicy"},
		},
	}

	// Recall first: without the deny this IS an escalation, so a pass below cannot come from the
	// detector simply not working.
	if inv := Build(base); len(inv.Privescs) != 1 {
		t.Fatalf("control: an unguarded projectIamAdmin binding must be an escalation, got %d", len(inv.Privescs))
	}

	denied := base
	denied.Denies = []RawGCPDeny{{
		DeniedPermissions: []string{"resourcemanager.projects.setIamPolicy"},
		DeniedPrincipals:  []string{member},
	}}
	if inv := Build(denied); len(inv.Privescs) != 0 {
		t.Errorf("an IAM DENY on setIamPolicy blocks this escalation — GCP evaluates deny before "+
			"allow — yet %d privesc(s) were reported: %+v", len(inv.Privescs), inv.Privescs)
	}
}

// A deny that does NOT cover this principal must not suppress anything. Over-reading a deny would
// trade false positives for false negatives, which on an attack-path page is the worse direction.
func TestDerivePrivesc_ADenyForSomeoneElseDoesNotSuppress(t *testing.T) {
	const member = "user:eve@corp.example"
	raw := RawGCP{
		ProjectID: "p1",
		Members:   []RawGCPMember{{Member: member}},
		Bindings: []RawGCPBinding{{
			Role: "roles/resourcemanager.projectIamAdmin", Members: []string{member},
		}},
		RoleDefs: map[string][]string{
			"roles/resourcemanager.projectIamAdmin": {"resourcemanager.projects.setIamPolicy"},
		},
		Denies: []RawGCPDeny{{
			DeniedPermissions: []string{"resourcemanager.projects.setIamPolicy"},
			DeniedPrincipals:  []string{"user:someone-else@corp.example"},
		}},
	}
	if inv := Build(raw); len(inv.Privescs) != 1 {
		t.Errorf("the deny names a different principal, so eve can still escalate: got %d", len(inv.Privescs))
	}
}

// An EXCEPTED principal is explicitly carved out of the deny, so the escalation stands for them.
func TestDerivePrivesc_AnExceptedPrincipalIsStillAnEscalation(t *testing.T) {
	const member = "user:eve@corp.example"
	raw := RawGCP{
		ProjectID: "p1",
		Members:   []RawGCPMember{{Member: member}},
		Bindings: []RawGCPBinding{{
			Role: "roles/resourcemanager.projectIamAdmin", Members: []string{member},
		}},
		RoleDefs: map[string][]string{
			"roles/resourcemanager.projectIamAdmin": {"resourcemanager.projects.setIamPolicy"},
		},
		Denies: []RawGCPDeny{{
			DeniedPermissions:   []string{"resourcemanager.projects.setIamPolicy"},
			DeniedPrincipals:    []string{member},
			ExceptionPrincipals: []string{member},
		}},
	}
	if inv := Build(raw); len(inv.Privescs) != 1 {
		t.Errorf("an excepted principal is not denied, so the escalation stands: got %d", len(inv.Privescs))
	}
}
