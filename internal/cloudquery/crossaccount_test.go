package cloudquery

import (
	"encoding/json"
	"strings"
	"testing"
)

const otherAccount = "999988887777"

// THE BUG THIS CLOSES. AWS grants same-account access if the identity policy OR the bucket policy
// allows; CROSS-account requires BOTH. canReadBucket passed SameAccount:true unconditionally, so a
// principal whose identity policy allowed s3:GetObject on a bucket in ANOTHER account was reported
// as having access — a path AWS would deny, and a fabricated route to somebody else's data.
func TestCanReadBucket_CrossAccountNeedsBothSides(t *testing.T) {
	principal := "arn:aws:iam::" + fixtureAccount + ":role/app"
	bucket := "arn:aws:s3:::someone-elses-pii"
	identity := parseDocs(raws(allowDoc("s3:GetObject", bucket)))

	// Identity allows, the other account's bucket policy says nothing.
	ok, cond := canReadBucket(principal, bucket, otherAccount, identity, nil, nil, nil)
	if ok {
		t.Fatalf("[FABRICATED] reported cross-account read with no bucket policy granting it (cond=%q)", cond)
	}

	// Same identity policy, same-account bucket: still allowed, and unconditional.
	ok, cond = canReadBucket(principal, bucket, fixtureAccount, identity, nil, nil, nil)
	if !ok {
		t.Fatal("[RECALL] lost same-account access that the identity policy plainly grants")
	}
	if cond != "" {
		t.Errorf("same-account access is not ownership-ambiguous, but was marked %q", cond)
	}
}

// Cross-account WITH both sides allowing is real access and must still be found.
func TestCanReadBucket_CrossAccountWithBothSidesIsAllowed(t *testing.T) {
	principal := "arn:aws:iam::" + fixtureAccount + ":role/app"
	bucket := "arn:aws:s3:::partner-shared"
	// Both sides must name the SAME resource for the cross-account AND to hold. s3:GetObject acts
	// on objects, so both grant on bucket/* — an identity policy on the bucket alone and a bucket
	// policy on its objects never meet, which is a real misconfiguration, not a modelling artefact.
	identity := parseDocs(raws(allowDoc("s3:GetObject", bucket+"/*")))
	policy := parseDoc(json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + principal + `"},"Action":"s3:GetObject","Resource":"` + bucket + `/*"}]}`))

	if ok, _ := canReadBucket(principal, bucket, otherAccount, identity, nil, nil, policy); !ok {
		t.Fatal("[RECALL] dropped a genuine cross-account grant where BOTH sides allow")
	}
}

// UNKNOWN ownership is the common case on estates that do not report it. Dropping the grant would
// lose real access everywhere; asserting it would fabricate. So it is kept AND marked conditional —
// but only when ownership actually changes the answer.
func TestCanReadBucket_UnknownOwnerIsKeptButConditional(t *testing.T) {
	principal := "arn:aws:iam::" + fixtureAccount + ":role/app"
	bucket := "arn:aws:s3:::unknown-owner"
	identity := parseDocs(raws(allowDoc("s3:GetObject", bucket)))

	ok, cond := canReadBucket(principal, bucket, "", identity, nil, nil, nil)
	if !ok {
		t.Fatal("[RECALL] dropped access because the estate did not report bucket ownership")
	}
	if cond == "" {
		t.Fatal("[OVERCLAIM] asserted access as proven when it holds only if the accounts match")
	}
	if !strings.Contains(cond, "owner account") {
		t.Errorf("condition does not say what is unknown: %q", cond)
	}
}

// ...and NOT conditional when ownership is irrelevant to the outcome, or the reader drowns in
// conditions that carry no information.
func TestCanReadBucket_UnknownOwnerIsNotConditionalWhenItCannotMatter(t *testing.T) {
	principal := "arn:aws:iam::" + fixtureAccount + ":role/app"
	bucket := "arn:aws:s3:::unknown-owner"

	// Neither side allows: same-account or cross-account, the answer is no.
	if ok, cond := canReadBucket(principal, bucket, "", nil, nil, nil, nil); ok || cond != "" {
		t.Errorf("no policy allows anything, yet got ok=%v cond=%q", ok, cond)
	}

	// BOTH sides allow: the answer is yes either way, so ownership is irrelevant.
	identity := parseDocs(raws(allowDoc("s3:GetObject", bucket+"/*")))
	policy := parseDoc(json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + principal + `"},"Action":"s3:GetObject","Resource":"` + bucket + `/*"}]}`))
	if ok, cond := canReadBucket(principal, bucket, "", identity, nil, nil, policy); !ok || cond != "" {
		t.Errorf("both sides allow, so ownership cannot change the answer; got ok=%v cond=%q", ok, cond)
	}
}
