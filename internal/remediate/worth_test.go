package remediate

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// WorthProposing filters the WORK QUEUE, never the evidence. These pin both halves of that: what
// earns a human's review slot, and what must never be silently promoted into one.
func TestWorthProposing(t *testing.T) {
	cases := []struct {
		name string
		f    types.Finding
		want bool
		why  string
	}{
		{"critical", types.Finding{Severity: types.SeverityCritical}, true, "worth interrupting someone"},
		{"high", types.Finding{Severity: types.SeverityHigh}, true, "worth a review slot"},
		{"medium", types.Finding{Severity: types.SeverityMedium}, false, "real, but not worth an approval request"},
		{"low", types.Finding{Severity: types.SeverityLow}, false, "the decoy class — noise that cost a review slot in 3/3 scenarios"},
		{"info", types.Finding{Severity: types.SeverityInfo}, false, "informational"},
		{
			"low but PROVEN", types.Finding{Severity: types.SeverityLow, VerificationStatus: types.VerificationVerified},
			true, "an exploit proved it — the severity label is the thing that was wrong, not the finding",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WorthProposing(tc.f); got != tc.want {
				t.Errorf("WorthProposing = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}
