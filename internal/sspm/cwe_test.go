package sspm

import "testing"

func TestCWEForRule(t *testing.T) {
	cases := map[string]string{
		"sspm::slack::2fa-not-enforced":     "CWE-287",
		"sspm::atlassian::sso-not-enforced": "CWE-287",
		"sspm::salesforce::modify-all-data": "CWE-269",
		"sspm::slack::admin-sprawl":         "CWE-269",
		"sspm::slack::app-broad-scope":      "CWE-269", // privilege beats the app- exposure bucket
		"sspm::slack::public-link-sharing":  "CWE-200",
		"sspm::zoom::recording-unprotected": "CWE-200",
		"sspm::slack::app-unverified":       "CWE-200",
	}
	for rule, want := range cases {
		got := cweForRule(rule)
		if len(got) != 1 || got[0] != want {
			t.Errorf("cweForRule(%q) = %v, want [%s]", rule, got, want)
		}
	}
	// Unrecognized → no CWE (keep inline-only; never a guess).
	if cweForRule("sspm::slack::something-novel") != nil {
		t.Error("an unrecognized rule must get NO CWE")
	}
}
