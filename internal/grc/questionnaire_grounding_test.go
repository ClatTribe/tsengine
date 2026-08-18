package grc

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// THE REGRESSION THIS FILE EXISTS FOR.
//
// A questionnaire answer is an attestation sent to someone else's procurement team. This
// used to derive answers from control GAPS alone, so a tenant with nothing connected and
// nothing scanned answered "Yes" to all ten questions — including "is MFA enforced?" —
// because no finding existed to contradict it. Absence of evidence was being reported as
// evidence of compliance, in the one document written to unblock an enterprise deal.
func TestFreshTenant_AnswersNothing(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	q, err := g.Questionnaire(context.Background(), "brand-new")
	if err != nil {
		t.Fatal(err)
	}
	if q.Yes != 0 {
		t.Errorf("a tenant with NOTHING connected answered %q to %d question(s) — that is an attestation "+
			"to a control nobody examined", AnswerYes, q.Yes)
	}
	if q.NotAssessed != len(q.Answers) {
		t.Errorf("NotAssessed = %d, want all %d", q.NotAssessed, len(q.Answers))
	}
	for _, a := range q.Answers {
		if a.Answer != AnswerNotAssessed {
			t.Errorf("%s answered %q with no evidence source connected", a.ID, a.Answer)
		}
		if len(a.MissingSources) == 0 {
			t.Errorf("%s is unanswered but does not say what to connect", a.ID)
		}
	}
}

// Connecting the source that can answer a question makes "Yes" legitimate — the fix must
// not simply refuse everything forever (that would under-claim as badly as it over-claimed).
func TestConnectedSource_MakesYesLegitimate(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	// An identity provider is what evidences the MFA question (AC-1, sources: identity).
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive})
	g := &GRC{Store: st}

	q, err := g.Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	var ac1 *QAnswer
	for i := range q.Answers {
		if q.Answers[i].ID == "AC-1" {
			ac1 = &q.Answers[i]
		}
	}
	if ac1 == nil {
		t.Fatal("AC-1 missing")
	}
	if ac1.Answer != AnswerYes {
		t.Errorf("with an identity provider connected and no gap, AC-1 = %q, want %q", ac1.Answer, AnswerYes)
	}
	// A question whose sources are still absent must remain unanswered.
	for _, a := range q.Answers {
		if a.ID == "CM-1" && a.Answer != AnswerNotAssessed {
			t.Errorf("CM-1 (container/cloud) = %q with neither connected, want %q", a.Answer, AnswerNotAssessed)
		}
	}
}

// A real gap still outranks everything — it is the most specific, best-evidenced answer,
// and it must stand whether or not we also count the source as connected.
func TestRealGap_StillReportsInProgress(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive})
	_ = st.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: "soc2", ControlID: "CC6.1",
		State: platform.ControlGap, EvidenceRefs: []string{"f-mfa"},
	})
	g := &GRC{Store: st}
	q, _ := g.Questionnaire(ctx, "t1")
	for _, a := range q.Answers {
		if a.ID != "AC-1" {
			continue
		}
		if a.Answer != AnswerInProgress {
			t.Fatalf("AC-1 with a real CC6.1 gap = %q, want %q", a.Answer, AnswerInProgress)
		}
		if len(a.EvidenceIDs) == 0 {
			t.Error("an In Progress answer must cite the finding that opened the gap")
		}
	}
}

// The document a customer SENDS must show the unanswered count prominently — a reader
// must not skim it and believe it was answered.
func TestMarkdown_DeclaresWhatWasNotAssessed(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	q, _ := g.Questionnaire(context.Background(), "brand-new")
	md := RenderQuestionnaireMarkdown(q)
	for _, want := range []string{"Not assessed", "not answered yet", "rather than assumed compliant", "connect "} {
		if !strings.Contains(md, want) {
			t.Errorf("rendered questionnaire missing %q", want)
		}
	}
}
