package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The verification ladder (ADR 0024 C3) has to survive the trip out of the agent. VerificationStatus
// is what grc/vapt counts as "tool-confirmed" in the auditor-facing report and what explain turns
// into an urgency sentence, so a rung flattened here is a rung flattened in front of a customer.
//
// The bug this pins: the status was the CONSTANT types.VerificationVerified, on every path, at every
// rung — so a path resting on nothing but our own inventory carried the tier reserved for one an
// independent method actively confirmed.
func TestCloudIssueToFinding_VerificationStatusFollowsTheRung(t *testing.T) {
	for _, tc := range []struct {
		name string
		is   cloudagent.Issue
		want types.VerificationState
	}{
		{
			// One source — our resolved-IAM graph. validatePath re-checks every edge, but against
			// the same graph, so nothing independent has agreed.
			name: "config-possible is the floor",
			is:   cloudagent.Issue{Target: "arn:aws:s3:::crown", Severity: "critical"},
			want: types.VerificationPatternMatch,
		},
		{
			// Our graph and the provider agreeing on a SUBSET: two independent assessments, nothing
			// fully re-fired. That is the corroborated tier's own definition.
			name: "partial provider coverage is corroborated",
			is: cloudagent.Issue{
				Target: "arn:aws:s3:::crown", Severity: "critical",
				AuthorizationCoverage: "2/5",
			},
			want: types.VerificationCorroborated,
		},
		{
			// Every authorization-requiring hop was put to the provider's own simulator and allowed.
			name: "provider-confirmed earns verified",
			is: cloudagent.Issue{
				Target: "arn:aws:s3:::crown", Severity: "critical",
				ProviderConfirmed: true, AuthorizationCoverage: "5/5",
			},
			want: types.VerificationVerified,
		},
		{
			// "0/0" means no hop on this path even required an authorization decision, so the
			// provider was asked nothing. Reading that as partial coverage would manufacture
			// corroboration out of an empty denominator.
			name: "zero-of-zero coverage is not corroboration",
			is: cloudagent.Issue{
				Target: "arn:aws:s3:::crown", Severity: "critical",
				AuthorizationCoverage: "0/0",
			},
			want: types.VerificationPatternMatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudIssueToFinding("f1", tc.is).VerificationStatus
			if got != tc.want {
				t.Fatalf("rung %q/%v → status %q, want %q",
					tc.is.AuthorizationCoverage, tc.is.ProviderConfirmed, got, tc.want)
			}
		})
	}
}

// The specific regression, stated as itself rather than as a table row: the old code returned
// verified unconditionally, and this is the input that made that a lie.
func TestCloudIssueToFinding_AnUncheckedPathIsNotVerified(t *testing.T) {
	f := cloudIssueToFinding("f1", cloudagent.Issue{Target: "arn:aws:s3:::crown", Severity: "critical"})
	if f.VerificationStatus == types.VerificationVerified {
		t.Fatal("a path no provider was asked about carries the tier reserved for one an " +
			"independent method actively confirmed — grc/vapt will count it as tool-confirmed in " +
			"the report a customer hands an auditor")
	}
}
