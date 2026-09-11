package auditreview

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

var now = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func key(f types.Finding) string { return f.RuleID + "|" + f.Endpoint }

func finding(id, rule, sev string, mods ...func(*types.Finding)) types.Finding {
	f := types.Finding{
		ID: id, RuleID: rule, Title: rule + " on /x", Endpoint: "https://app.example/x",
		Severity: types.Severity(sev),
	}
	for _, m := range mods {
		m(&f)
	}
	return f
}

func exploited(f *types.Finding) {
	f.Tool = "webagent"
	f.VerificationStatus = types.VerificationVerified
}

// THE REFUSALS. Each is a case where accepting the input would put something unsupportable into a
// document a third party relies on.
func TestDecide_RefusesWhatCannotGoIntoASignedReport(t *testing.T) {
	for _, c := range []struct {
		name             string
		v                Verdict
		severity, reason string
		by               string
		want             error
	}{
		{"unknown verdict", Verdict("maybe"), "", "because", "Ada", ErrVerdict},
		{"nobody signing an inclusion", VerdictInclude, "", "", "", ErrNoReviewer},
		{"exclusion with no reason", VerdictExclude, "", "", "Ada", ErrNoReason},
		{"reclassification with no reason", VerdictReclassify, "low", "", "Ada", ErrNoReason},
		{"reclassification with no severity", VerdictReclassify, "", "not exploitable here", "Ada", ErrSeverity},
		{"reclassification to nonsense", VerdictReclassify, "spicy", "not exploitable here", "Ada", ErrSeverity},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decide("t1", "app", "k", c.v, c.severity, c.reason, c.by, now)
			if !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}

	// An INCLUSION needs no reason — the engine's evidence is the reason. Requiring one would make
	// the common case expensive, which is the opposite of the point.
	if _, err := Decide("t1", "app", "k", VerdictInclude, "", "", "Ada", now); err != nil {
		t.Errorf("a plain inclusion was refused: %v", err)
	}
}

// A reclassification that LOWERS severity is the risky direction — it makes a report look better and
// is what a later compromise exposes — so the direction is recorded rather than inferred by a reader.
func TestMarkDirection_RecordsALoweringAsTheReviewersOwnJudgement(t *testing.T) {
	d, err := Decide("t1", "app", "k", VerdictReclassify, "low", "internal-only endpoint", "Ada", now)
	if err != nil {
		t.Fatal(err)
	}
	if got := MarkDirection(d, "high"); !got.Lowered {
		t.Error("lowering high→low was not recorded as a lowering")
	}
	if got := MarkDirection(d, "info"); got.Lowered {
		t.Error("raising info→low was recorded as a lowering")
	}
}

// The order IS the compression: undecided first, then the ones where the reviewer must supply the
// judgement the engine could not, then by severity. Spreading an hour evenly over twelve findings is
// what this replaces.
func TestBuild_PutsTheExpensiveMinutesAtTheTop(t *testing.T) {
	fs := []types.Finding{
		finding("f1", "nuclei::weak-tls", "low"),
		finding("f2", "webagent::sqli", "critical", exploited),
		finding("f3", "nuclei::xss-reflected", "high"),
	}
	r := Build("app", "OWASP Top 10 (2021)", fs, key, nil)
	if len(r.Items) != 3 {
		t.Fatalf("items = %d", len(r.Items))
	}
	// The two unproven ones lead, worst first; the exploitation-proven critical sorts last because
	// it is the cheapest to review, not the least important.
	if r.Items[0].RuleID != "nuclei::xss-reflected" || r.Items[1].RuleID != "nuclei::weak-tls" {
		t.Errorf("order = %s, %s, %s — unproven findings must lead",
			r.Items[0].RuleID, r.Items[1].RuleID, r.Items[2].RuleID)
	}
	if !r.Items[2].Proven {
		t.Error("the exploited finding was not marked proven, so the load split is wrong")
	}
	if r.Progress.Load.Proven != 1 || r.Progress.Load.Unproven != 2 {
		t.Errorf("load = %+v", r.Progress.Load)
	}
	if !strings.Contains(r.Progress.Load.Detail, "judgement is actually needed") {
		t.Errorf("the load detail does not say where the reviewer is needed: %q", r.Progress.Load.Detail)
	}
}

// An EMPTY review is not a clean application — it is just as likely a scan that never ran. This is
// the same refusal recertify and training make, on the artifact where it matters most.
func TestBuild_AnEmptyReviewIsNotComplete(t *testing.T) {
	r := Build("app", "", nil, key, nil)
	if r.Progress.Complete {
		t.Error("a review with nothing in it reported complete")
	}
	if !strings.Contains(r.Progress.Detail, "NOT a completed audit") {
		t.Errorf("the empty case does not say so: %q", r.Progress.Detail)
	}
}

// Decisions survive a re-scan: the tender flow re-tests between draft and final report, so finding
// IDs move while the key does not.
func TestBuild_DecisionsSurviveARescanButANewFindingReopensTheReview(t *testing.T) {
	d, err := Decide("t1", "app", "nuclei::weak-tls|https://app.example/x", VerdictInclude, "", "", "Ada", now)
	if err != nil {
		t.Fatal(err)
	}
	rescan := []types.Finding{finding("DIFFERENT-ID", "nuclei::weak-tls", "low")}
	r := Build("app", "", rescan, key, []Disposition{d})
	if !r.Progress.Complete || r.Items[0].By != "Ada" {
		t.Fatalf("the decision did not survive a re-scan: %+v", r.Progress)
	}

	withNew := append(rescan, finding("f9", "nuclei::open-redirect", "medium"))
	r2 := Build("app", "", withNew, key, []Disposition{d})
	if r2.Progress.Complete {
		t.Error("a finding nobody has seen left the review reporting complete")
	}
	if r2.Progress.Pending != 1 {
		t.Errorf("pending = %d, want 1", r2.Progress.Pending)
	}
}

// A disposition recorded for a DIFFERENT application must not satisfy this one.
func TestBuild_DecisionsDoNotLeakBetweenApplications(t *testing.T) {
	d, _ := Decide("t1", "other-app", "nuclei::weak-tls|https://app.example/x", VerdictInclude, "", "", "Ada", now)
	r := Build("app", "", []types.Finding{finding("f1", "nuclei::weak-tls", "low")}, key, []Disposition{d})
	if r.Progress.Complete {
		t.Error("another application's decision completed this review")
	}
}
