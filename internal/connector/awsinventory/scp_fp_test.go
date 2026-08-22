package awsinventory

import "testing"

const (
	createKeyAllow = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}`
	// An SCP that permits everything EXCEPT the escalating call. This is how an org guardrail is
	// actually written: a broad allow with the dangerous action carved out.
	scpDenyCreateKey = `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"}]}`
	scpAllowAll = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
)

func userWith(policies []string, scps []string) RawAWS {
	return RawAWS{
		AccountID: "111122223333",
		Users: []RawIAMUser{{
			Name: "eve", ARN: "arn:aws:iam::111122223333:user/eve", PoliciesJSON: policies,
		}},
		SCPsJSON: scps,
	}
}

// THE FALSE-POSITIVE CONTROL, on the other named cloud. An AWS Organizations SCP is the ceiling: an
// identity policy granting iam:CreateAccessKey does not permit it if no SCP allows it.
//
// cloudiam.PolicySet has always had SCPs and evaluated them. RawAWS could not EXPRESS one, so the
// ingest built its PolicySet without any and an account governed by an org guardrail was still
// reported as having a privilege-escalation path — the false positive landing hardest on the estates
// well-run enough to have an Organization.
func TestAddPrivesc_AnSCPCeilingBlocksTheEscalation(t *testing.T) {
	// Recall first: with no SCP this IS an escalation, so a pass below cannot come from the detector
	// simply not firing.
	if inv := Build(userWith([]string{createKeyAllow}, nil)); len(inv.Privescs) != 1 {
		t.Fatalf("control: an unguarded iam:CreateAccessKey grant must be an escalation, got %d", len(inv.Privescs))
	}

	if inv := Build(userWith([]string{createKeyAllow}, []string{scpDenyCreateKey})); len(inv.Privescs) != 0 {
		t.Errorf("an SCP carving out iam:CreateAccessKey is the org ceiling — the identity policy "+
			"cannot exceed it — yet %d privesc(s) were reported: %+v", len(inv.Privescs), inv.Privescs)
	}
}

// An SCP that permits the action must NOT suppress. Over-reading a ceiling trades false positives
// for false negatives, and on an attack-path page that is the worse direction.
func TestAddPrivesc_APermissiveSCPDoesNotSuppress(t *testing.T) {
	if inv := Build(userWith([]string{createKeyAllow}, []string{scpAllowAll})); len(inv.Privescs) != 1 {
		t.Errorf("this SCP allows everything, so the escalation stands: got %d", len(inv.Privescs))
	}
}

// An unreadable SCP is SKIPPED, not treated as denying everything — the same direction the
// permission boundary takes. Pruning a path on a ceiling we could not read would hide real
// escalations behind an unparseable document.
func TestAddPrivesc_AnUnreadableSCPDoesNotSilentlyClearTheAccount(t *testing.T) {
	if inv := Build(userWith([]string{createKeyAllow}, []string{`<!DOCTYPE html>access denied`})); len(inv.Privescs) != 1 {
		t.Errorf("an SCP we could not parse must not suppress a real escalation: got %d", len(inv.Privescs))
	}
}
