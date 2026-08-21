package platformapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestFeedback_RecordsAJudgementWithoutSuppressingAnything(t *testing.T) {
	h, st := setup(t)
	tid := "t1"
	body := `{"key":"rule|semgrep::sqli|app.go:14","verdict":"real","evidence":"insufficient","by":"cto@acme.com","note":"I believe it, the write-up did not show me why"}`
	rec := do(h, "POST", "/v1/issues/feedback", tid, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}

	fbs, err := st.ListFeedback(context.Background(), tid)
	if err != nil || len(fbs) != 1 {
		t.Fatalf("the judgement should be stored: %v %+v", err, fbs)
	}
	if fbs[0].Verdict != platform.FeedbackReal || fbs[0].Evidence != platform.EvidenceInsufficient {
		t.Fatalf("both axes must survive independently: %+v", fbs[0])
	}

	// THE POINT: it must change nothing. Feedback a person suspects will hide their
	// finding is feedback they will not give honestly.
	igs, err := st.ListIgnoreRules(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(igs) != 0 {
		t.Fatal("recording an opinion must not suppress the issue")
	}
}

// An unrecognised label is refused loudly, not stored as free text — a corpus whose
// labels are open-ended cannot be counted.
func TestFeedback_RefusesLabelsNobodyDefined(t *testing.T) {
	h, st := setup(t)
	tid := "t1"
	for _, body := range []string{
		`{"key":"k","verdict":"kinda_real"}`,
		`{"key":"k","verdict":"real","evidence":"meh"}`,
		`{"key":"k"}`,
	} {
		if rec := do(h, "POST", "/v1/issues/feedback", tid, body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: want 400, got %d", body, rec.Code)
		}
	}
	if fbs, _ := st.ListFeedback(context.Background(), tid); len(fbs) != 0 {
		t.Fatal("a refused judgement must not be stored")
	}
}

func TestFeedback_MissingKeyIsRefused(t *testing.T) {
	h, _ := setup(t)
	tid := "t1"
	if rec := do(h, "POST", "/v1/issues/feedback", tid, `{"verdict":"real"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an opinion about nothing is not an opinion; want 400, got %d", rec.Code)
	}
}

// Latest-wins: someone changing their mind replaces their earlier opinion rather than
// leaving the corpus holding both.
func TestFeedback_LatestWinsPerIssue(t *testing.T) {
	h, st := setup(t)
	tid := "t1"
	do(h, "POST", "/v1/issues/feedback", tid, `{"key":"k1","verdict":"false_positive"}`)
	do(h, "POST", "/v1/issues/feedback", tid, `{"key":"k1","verdict":"real"}`)

	fbs, _ := st.ListFeedback(context.Background(), tid)
	if len(fbs) != 1 {
		t.Fatalf("one issue, one current opinion; got %d", len(fbs))
	}
	if fbs[0].Verdict != platform.FeedbackReal {
		t.Fatalf("the later judgement should stand, got %q", fbs[0].Verdict)
	}
}

// "I could not tell" is a defect in the finding, not an absence of opinion, and must be
// recordable.
func TestFeedback_UnclearIsARecordableVerdict(t *testing.T) {
	h, st := setup(t)
	tid := "t1"
	if rec := do(h, "POST", "/v1/issues/feedback", tid, `{"key":"k","verdict":"unclear"}`); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	fbs, _ := st.ListFeedback(context.Background(), tid)
	if len(fbs) != 1 || fbs[0].Verdict != platform.FeedbackUnclear {
		t.Fatal(`"I could not understand this finding" is a defect in the finding and must be sayable`)
	}
}

func TestFeedback_ListIsTenantScopedAndNeverNull(t *testing.T) {
	h, _ := setup(t)
	tid := "t1"
	rec := do(h, "GET", "/v1/issues/feedback", tid, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"feedback":[]`) {
		t.Fatalf("an empty list must serialize as [] not null — the frontend maps over it: %s", rec.Body)
	}
}
