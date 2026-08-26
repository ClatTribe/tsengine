package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func attestDeps(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", GRC: &grc.GRC{Store: st}}
	return NewHandler(d), st
}

// THE REFUSAL. An observed question is checked on every scan, so accepting a typed answer for
// one would let an assertion overwrite an observation — silently, in a document published to
// someone else's procurement team. Driven through the mux rather than the handler function,
// because a refusal nobody can reach is not one.
func TestAttestIsRefusedOnAnEvidencedQuestion(t *testing.T) {
	h, st := attestDeps(t)
	rec := authed(t, h, "POST", "/v1/questionnaire/attest/AC-1", "t1",
		`{"in_place":true,"by":"Someone Optimistic"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a measured question accepted a typed answer: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["reason"] != "not_attestable" {
		t.Errorf("refusal carries no machine-readable reason: %v", body)
	}
	if !strings.Contains(body["error"], "opinion") {
		t.Errorf("the refusal does not explain itself: %q", body["error"])
	}
	tn, _ := st.GetTenant(context.Background(), "t1")
	if len(tn.QuestionnaireAttestations) != 0 {
		t.Errorf("the refused answer was stored anyway: %v", tn.QuestionnaireAttestations)
	}
}

func TestAttestRecordsAnAttestedQuestion(t *testing.T) {
	h, st := attestDeps(t)
	rec := authed(t, h, "POST", "/v1/questionnaire/attest/HR-1", "t1",
		`{"in_place":true,"by":"Dana Officer","note":"annual, via Certn"}`)
	if rec.Code != 200 {
		t.Fatalf("attest: %d %s", rec.Code, rec.Body.String())
	}
	tn, _ := st.GetTenant(context.Background(), "t1")
	a, ok := tn.QuestionnaireAttestations["HR-1"]
	if !ok {
		t.Fatal("nothing stored")
	}
	if !a.InPlace || a.By != "Dana Officer" || a.At == "" {
		t.Errorf("stored attestation is incomplete: %+v", a)
	}

	// And it reaches the rendered document AS AN ASSERTION — named, not presented as evidence.
	q, err := (&grc.GRC{Store: st}).Questionnaire(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	md := grc.RenderQuestionnaireMarkdown(q)
	if !strings.Contains(md, "stated by Dana Officer") {
		t.Error("the answer does not name who stated it, so it reads as something we established")
	}
}

func TestAttestRequiresANamedHuman(t *testing.T) {
	// The name is what distinguishes this row from an evidenced one when a buyer reads it.
	// Without it the document would publish an anonymous claim.
	h, st := attestDeps(t)
	rec := authed(t, h, "POST", "/v1/questionnaire/attest/HR-1", "t1", `{"in_place":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unsigned attestation was accepted: %d %s", rec.Code, rec.Body.String())
	}
	tn, _ := st.GetTenant(context.Background(), "t1")
	if len(tn.QuestionnaireAttestations) != 0 {
		t.Error("an unattributed answer was stored")
	}
}

func TestAttestRejectsAnUnknownQuestion(t *testing.T) {
	h, _ := attestDeps(t)
	if rec := authed(t, h, "POST", "/v1/questionnaire/attest/NOPE-9", "t1",
		`{"in_place":true,"by":"Dana"}`); rec.Code != http.StatusNotFound {
		t.Errorf("recorded an answer to a question that does not exist: %d", rec.Code)
	}
}

// A "no" is a real answer and must be publishable. A questionnaire that could only say yes is a
// form with one possible answer, and a vendor honestly reporting a gap is giving the buyer
// exactly what they asked for.
func TestAttestCanRecordANo(t *testing.T) {
	h, st := attestDeps(t)
	if rec := authed(t, h, "POST", "/v1/questionnaire/attest/GV-3", "t1",
		`{"in_place":false,"by":"Dana Officer","note":"quoted, not yet bound"}`); rec.Code != 200 {
		t.Fatalf("attest: %d %s", rec.Code, rec.Body.String())
	}
	q, _ := (&grc.GRC{Store: st}).Questionnaire(context.Background(), "t1")
	for _, a := range q.Answers {
		if a.ID == "GV-3" {
			if a.Answer != grc.AnswerNo {
				t.Errorf("GV-3 = %q, want %q", a.Answer, grc.AnswerNo)
			}
			return
		}
	}
	t.Error("GV-3 missing from the questionnaire")
}
