package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleQuestionnaireAttest (POST /v1/questionnaire/attest/{id}) records a named human's answer
// to a security-questionnaire question no scan can reach — background checks, physical security,
// whether the recovery plan was actually tested.
//
// The refusal that makes the rest trustworthy: an OBSERVED question is rejected. Those are
// checked on every scan, and accepting a typed answer for one would let an assertion overwrite an
// observation — silently, and in a document published to someone else's procurement team. The
// same rule internal/ctoreadiness enforces for its measured rows, for the same reason.
//
// The answer is signed into the ledger (§18.2 inv. 4) because an attestation is a person putting
// their name to a claim that a stranger will rely on.
func (d Deps) handleQuestionnaireAttest(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := strings.TrimSpace(r.PathValue("id"))
	var body struct {
		InPlace bool   `json:"in_place"`
		By      string `json:"by"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read the answer"))
		return
	}
	if strings.TrimSpace(body.By) == "" {
		// An unattributed attestation is not one. The name is what distinguishes this answer
		// from an evidenced one when the document is read, so an answer without it would be
		// published as an anonymous claim.
		writeJSON(w, http.StatusBadRequest, errBody("name the person answering — the questionnaire states it"))
		return
	}

	q := grc.QuestionByID(id)
	if q == nil {
		writeJSON(w, http.StatusNotFound, errBody("no such question"))
		return
	}
	if q.Evidence != grc.QAttested {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this question is answered from live evidence, not by hand — we check it on every " +
				"scan, so a typed answer would replace an observation with an opinion in a document " +
				"your buyer relies on",
			"reason": "not_attestable",
		})
		return
	}

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if t.QuestionnaireAttestations == nil {
		t.QuestionnaireAttestations = map[string]platform.QuestionnaireAttestation{}
	}
	a := platform.QuestionnaireAttestation{
		InPlace: body.InPlace, By: strings.TrimSpace(body.By),
		At: time.Now().UTC().Format(time.RFC3339), Note: strings.TrimSpace(body.Note),
	}
	t.QuestionnaireAttestations[id] = a
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("questionnaire question answered", "questionnaire_attest",
			map[string]any{"tenant_id": tenantID, "question": id, "in_place": body.InPlace, "by": a.By},
			"security questionnaire attestation")
	}
	writeJSON(w, http.StatusOK, map[string]any{"question": id, "attestation": a})
}
