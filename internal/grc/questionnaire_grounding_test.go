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
	// Every question is unanswered, but the TWO KINDS of unanswered are reported separately —
	// they need different action. "Not assessed" is fixed by connecting a system; "Needs your
	// answer" is fixed by a person sitting down and answering, and no amount of connecting will
	// do it. Merged, the reader is told to fix the wrong thing.
	if q.NotAssessed+q.NeedsYou != len(q.Answers) {
		t.Errorf("NotAssessed(%d) + NeedsYou(%d) = %d, want all %d unanswered",
			q.NotAssessed, q.NeedsYou, q.NotAssessed+q.NeedsYou, len(q.Answers))
	}
	if q.NotAssessed == 0 || q.NeedsYou == 0 {
		t.Errorf("both kinds of unanswered should be present on a fresh tenant, got NotAssessed=%d NeedsYou=%d",
			q.NotAssessed, q.NeedsYou)
	}
	for _, a := range q.Answers {
		switch a.Evidence {
		case QAttested:
			if a.Answer != AnswerNeedsYou {
				t.Errorf("%s is attested and nobody has answered it, but reads %q", a.ID, a.Answer)
			}
			if a.AttestedBy != "" {
				t.Errorf("%s reports an attester (%q) nobody supplied", a.ID, a.AttestedBy)
			}
			if a.Why == "" {
				t.Errorf("%s needs a human answer but never says why we cannot answer it ourselves", a.ID)
			}
		default:
			if a.Answer != AnswerNotAssessed {
				t.Errorf("%s answered %q with no evidence source connected", a.ID, a.Answer)
			}
			if len(a.MissingSources) == 0 {
				t.Errorf("%s is unanswered but does not say what to connect", a.ID)
			}
		}
	}
}

// An attested question must NEVER be resolved from findings. Its control mapping exists so the
// answer can cite what it speaks to — not as a route to inferring it. Letting a finding decide
// "have your employees had background checks?" would invent an observation out of an unrelated
// one, in a document sent to someone else's procurement team.
func TestAttestedQuestionIsNeverInferredFromFindings(t *testing.T) {
	st := store.NewMemory()
	g := &GRC{Store: st}
	ctx := context.Background()
	fullyOnboarded(t, st, "t1")

	attested := map[string]bool{}
	for _, q := range standardQuestionnaire() {
		if q.Evidence == QAttested {
			attested[q.ID] = true
		}
	}
	if len(attested) == 0 {
		t.Fatal("no attested questions in the corpus — this guard is not running")
	}

	q, err := g.Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range q.Answers {
		if !attested[a.ID] {
			continue
		}
		if a.Answer != AnswerNeedsYou {
			t.Errorf("%s is attested and unanswered, but a fully-onboarded tenant resolved it to %q — "+
				"connecting systems must not answer a question no scan can reach", a.ID, a.Answer)
		}
		if len(a.GapControls) > 0 || len(a.EvidenceIDs) > 0 {
			t.Errorf("%s cited findings (%v / %v) for a question nothing can observe", a.ID, a.GapControls, a.EvidenceIDs)
		}
	}
}

// The mirror: a real attestation is honoured, and BOTH answers are recordable. A questionnaire
// that could not say no would be a form with one possible answer.
func TestAttestationIsHonouredInBothDirections(t *testing.T) {
	st := store.NewMemory()
	g := &GRC{Store: st}
	ctx := context.Background()

	var yesID, noID string
	for _, q := range standardQuestionnaire() {
		if q.Evidence != QAttested {
			continue
		}
		if yesID == "" {
			yesID = q.ID
		} else if noID == "" {
			noID = q.ID
		}
	}
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", QuestionnaireAttestations: map[string]platform.QuestionnaireAttestation{
		yesID: {InPlace: true, By: "Dana Officer", At: "2026-08-26T00:00:00Z"},
		noID:  {InPlace: false, By: "Dana Officer", At: "2026-08-26T00:00:00Z", Note: "planned for Q4"},
	}}); err != nil {
		t.Fatal(err)
	}

	q, err := g.Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]QAnswer{}
	for _, a := range q.Answers {
		byID[a.ID] = a
	}
	if got := byID[yesID]; got.Answer != AnswerYes || got.AttestedBy != "Dana Officer" {
		t.Errorf("%s = %q by %q, want Yes attributed to the attester", yesID, got.Answer, got.AttestedBy)
	}
	if got := byID[noID]; got.Answer != AnswerNo || got.AttestedNote != "planned for Q4" {
		t.Errorf("%s = %q note %q, want a recorded No — a vendor honestly saying no is the answer the buyer asked for",
			noID, got.Answer, got.AttestedNote)
	}
	if q.No != 1 {
		t.Errorf("No = %d, want 1 counted as its own outcome rather than folded into unanswered", q.No)
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
	for _, want := range []string{
		"Not assessed", "no evidence source connected", "rather than assumed compliant", "connect ",
		// The second admission, stated separately: a question awaiting OUR answer is not one
		// waiting on an integration, and telling the reader to connect something would send
		// them to fix the wrong thing.
		"awaiting an answer from us", "need a person",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("rendered questionnaire missing %q", want)
		}
	}
}

// An attested answer must be visibly an assertion. Rendered like an evidenced one, a buyer
// cannot tell "a scanner confirmed this" from "somebody typed yes", which is the entire
// distinction the attested tier exists to preserve.
func TestMarkdown_AttributesAttestedAnswersToTheirAuthor(t *testing.T) {
	st := store.NewMemory()
	g := &GRC{Store: st}
	ctx := context.Background()
	var id string
	for _, q := range standardQuestionnaire() {
		if q.Evidence == QAttested {
			id = q.ID
			break
		}
	}
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", QuestionnaireAttestations: map[string]platform.QuestionnaireAttestation{
		id: {InPlace: true, By: "Dana Officer", At: "2026-08-26T00:00:00Z"},
	}}); err != nil {
		t.Fatal(err)
	}
	q, _ := g.Questionnaire(ctx, "t1")
	md := RenderQuestionnaireMarkdown(q)
	if !strings.Contains(md, "stated by Dana Officer") {
		t.Error("an attested Yes does not name who stated it — it reads as evidence we established")
	}
	// The DATE matters as much as the name: the age of an attestation is part of what it is
	// worth, and "tested within the last twelve months" answered three years ago is not the
	// same answer. Written the way a person would, not as a machine timestamp — this document
	// is read by someone else's procurement team.
	if !strings.Contains(md, "on 26 Aug 2026") {
		t.Errorf("attested answer does not carry a readable date:\n%s", md)
	}
	if strings.Contains(md, "2026-08-26T00:00:00Z") {
		t.Error("a raw RFC3339 timestamp reached the buyer-facing document")
	}
	if !strings.Contains(md, "they are an") || !strings.Contains(md, "assertion") {
		t.Error("the document never tells the reader that attested rows are assertions rather than observations")
	}
}
