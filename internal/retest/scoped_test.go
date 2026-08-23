package retest

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func scopedAction(keys ...string) platform.Action {
	return platform.Action{ID: "a1", Status: platform.ActApplied, FindingKeys: keys}
}

// An action claims to resolve a SET of findings. Confirming it while one member's producer was never
// re-run reports the whole remediation closed on partial evidence — and FixStatusFixed is TERMINAL,
// so there is no later pass to correct it. Hence ALL, not ANY.
func TestVerifyScoped_APartiallyObservableActionIsNotConfirmed(t *testing.T) {
	act := scopedAction(
		"nuclei::sqli|https://app.example.com/search",     // covered: nuclei ran
		"cloudagent::attack-path::abc|arn:aws:s3:::crown", // NOT covered: nothing re-ran the agent
	)
	cov := detect.CoverageOf("nuclei")

	changed := VerifyScoped([]platform.Action{act}, nil, time.Unix(0, 0).UTC(), cov)
	for _, a := range changed {
		if a.Verification != nil && a.Verification.Status == platform.FixStatusFixed {
			t.Fatalf("confirmed a fix on partial evidence (%q) — one of its findings comes from a "+
				"producer this pass never ran, and the record is terminal", a.Verification.Evidence)
		}
	}
}

// The mirror: when every producer really did run, the fix is still confirmed. Trading a false
// confirmation for never confirming anything is the same failure pointed the other way.
func TestVerifyScoped_AFullyObservedActionIsStillConfirmed(t *testing.T) {
	act := scopedAction("nuclei::sqli|https://app.example.com/search")
	changed := VerifyScoped([]platform.Action{act}, nil, time.Unix(0, 0).UTC(), detect.CoverageOf("nuclei"))
	if len(changed) != 1 || changed[0].Verification == nil ||
		changed[0].Verification.Status != platform.FixStatusFixed {
		t.Fatal("nuclei ran and the finding is gone — that is exactly the evidence a confirmed fix rests on")
	}
}

// A finding that is STILL PRESENT is a negative claim, and a negative claim needs no absence
// argument: we observed it. Coverage must not suppress it, or a fix that demonstrably did not work
// would go unreported.
func TestVerifyScoped_StillPresentIsReportedRegardless(t *testing.T) {
	key := "nuclei::sqli|https://app.example.com/search"
	present := []types.Finding{{RuleID: "nuclei::sqli", Endpoint: "https://app.example.com/search"}}
	changed := VerifyScoped([]platform.Action{scopedAction(key)}, present, time.Unix(0, 0).UTC(),
		detect.CoverageOf("nuclei"))
	if len(changed) != 1 || changed[0].Verification.Status != platform.FixStatusStillPresent {
		t.Fatal("the finding was observed and is still there; that must be reported")
	}
}
