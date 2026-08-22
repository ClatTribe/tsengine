package cloudiam

import "testing"

// AWS's IAM API returns PolicyDocument URL-ENCODED — GetRolePolicy, GetUserPolicy and
// GetPolicyVersion all do, and the API documentation says so. A collector that forwards that
// string verbatim is doing the obvious thing, and before this every such document failed to
// parse, was skipped as unreadable, and the account came back with no escalation paths and
// nothing saying why.
//
// That is the worst possible output for a security product: a confident all-clear over an
// account in which nothing was evaluated.
func TestParse_AcceptsTheURLEncodedFormTheAWSAPIReturns(t *testing.T) {
	const plain = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}`
	// Exactly what GetRolePolicy hands back for the document above.
	const encoded = `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22iam%3ACreateAccessKey%22%2C%22Resource%22%3A%22*%22%7D%5D%7D`

	want, err := Parse([]byte(plain))
	if err != nil {
		t.Fatalf("plain form must parse: %v", err)
	}
	got, err := Parse([]byte(encoded))
	if err != nil {
		t.Fatalf("the URL-encoded form AWS actually returns must parse: %v", err)
	}
	if len(got.Statement) != len(want.Statement) || len(got.Statement) != 1 {
		t.Fatalf("decoded document does not match the plain one: %+v vs %+v", got, want)
	}

	// And the decoded document must be USABLE, not merely non-nil: a parse that yields an empty
	// shell would still report no escalation while looking like it worked.
	dec, _ := Eval("iam:CreateAccessKey", "*", got)
	if dec != Allow {
		t.Errorf("the decoded policy must evaluate like the plain one, got %v", dec)
	}
}

// The fallback is a decode, not a guess. Something that is not a policy in either form stays an
// error — and the error must be about the JSON, since a url-decode failure is not the interesting
// half of "this is not a policy".
func TestParse_StillRejectsWhatIsNotAPolicyInEitherForm(t *testing.T) {
	for _, in := range []string{"", "not json", "%7Bnot json%7D", "<xml/>"} {
		if d, err := Parse([]byte(in)); err == nil || d != nil {
			t.Errorf("Parse(%q) = (%v, %v), want an error — accepting this would turn an unreadable "+
				"document into an empty policy that silently permits nothing", in, d, err)
		}
	}
}
