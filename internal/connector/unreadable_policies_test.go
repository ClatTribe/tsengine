package connector

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

func role(name string, docs ...string) awsinventory.RawIAMRole {
	return awsinventory.RawIAMRole{
		Name: name, ARN: "arn:aws:iam::111122223333:role/" + name, PoliciesJSON: docs,
	}
}

// A policy that is PRESENT but unreadable was invisible to CoverAWS: withPolicies counted it, so the
// no-policies note did not fire, while the ingest skipped every unparseable document and the account
// came back with no escalation paths.
//
// "We could not read your policies" and "nobody can escalate" then look identical, and only one of
// them is true.
func TestCoverAWS_NamesPrincipalsWhosePoliciesCouldNotBeRead(t *testing.T) {
	raw := awsinventory.RawAWS{Roles: []awsinventory.RawIAMRole{
		role("admin-maker", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}`),
		role("mystery-role", `<!DOCTYPE html><html>access denied</html>`),
	}}

	c := CoverAWS(raw)
	note := c.Notes["unreadable-policies"]
	if note == "" {
		t.Fatal("a principal whose policy documents cannot be parsed must be NAMED. Silence here " +
			"reports an unevaluated account as one with no escalation paths.")
	}
	if !strings.Contains(note, "mystery-role") {
		t.Errorf("the note must name the affected principal, got %q", note)
	}
	if strings.Contains(note, "admin-maker") {
		t.Errorf("a principal whose policy DID parse must not be named — it was evaluated, and "+
			"naming it makes the note noise people learn to skip: %q", note)
	}
}

// Every, not any. A principal with one bad document and one good one WAS evaluated against the good
// one, so its escalations are reported and it is not the silent case this note exists for.
func TestCoverAWS_DoesNotNameAPrincipalItStillEvaluated(t *testing.T) {
	raw := awsinventory.RawAWS{Roles: []awsinventory.RawIAMRole{
		role("partly-readable",
			`garbage`,
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
	}}
	if note := CoverAWS(raw).Notes["unreadable-policies"]; note != "" {
		t.Errorf("this principal was evaluated against its readable policy, so it is not unread: %q", note)
	}
}

// The URL-encoded form AWS's own API returns is now readable, so it must NOT be reported as a gap —
// that would replace a false all-clear with a false alarm on the most common snapshot there is.
func TestCoverAWS_TheAWSURLEncodedFormIsNotAGap(t *testing.T) {
	raw := awsinventory.RawAWS{Roles: []awsinventory.RawIAMRole{
		role("encoded", `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22iam%3ACreateAccessKey%22%2C%22Resource%22%3A%22*%22%7D%5D%7D`),
	}}
	if note := CoverAWS(raw).Notes["unreadable-policies"]; note != "" {
		t.Errorf("cloudiam.Parse reads this form now: %q", note)
	}
	// And it must actually produce the escalation, not merely avoid the warning.
	inv := awsinventory.Build(raw)
	if len(inv.Privescs) != 1 {
		t.Errorf("the URL-encoded policy grants iam:CreateAccessKey on *, so it is an escalation "+
			"path: got %d privescs %+v", len(inv.Privescs), inv.Privescs)
	}
}

// A clean, fully-readable snapshot stays quiet.
func TestCoverAWS_ReadablePoliciesProduceNoNote(t *testing.T) {
	raw := awsinventory.RawAWS{Roles: []awsinventory.RawIAMRole{
		role("ok", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
	}}
	if note := CoverAWS(raw).Notes["unreadable-policies"]; note != "" {
		t.Errorf("nothing was unreadable: %q", note)
	}
}
