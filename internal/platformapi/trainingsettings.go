package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// trainingsettings.go closes the customer end of the feedback loop: the one place a
// tenant decides whether their agent runs may improve the product (ADR 0018 §4).
//
// It has to be a STANDING decision rather than a per-run prompt, because consent must be
// in hand before the data exists. ledger.GrantConsent refuses once an episode has closed
// for exactly that reason, so a UI that asked afterwards would be asking a question the
// system is built to refuse to act on.

// defaultTrainingStatement is what a customer agrees to when they say yes here. It is
// stored VERBATIM on each consent so an auditor reads the actual words, and it is
// deliberately narrow: what we keep, what we do not, and that saying no changes nothing
// about the security work.
const defaultTrainingStatement = "We may use the recorded steps and outcomes of agent runs on this " +
	"workspace to improve tsengine's detection and remediation. This covers the agent's own tool calls, " +
	"the findings it produced, and whether a fix closed them. Declining changes nothing about the " +
	"security work performed for this workspace."

// resolveTrainingConsent returns the tenant's standing decision. Unconfigured, or
// unreadable, is NOT CONSENTED — silence is not agreement, and a read error must not
// become a yes.
func (d Deps) resolveTrainingConsent(ctx context.Context, tenantID string) platform.TrainingConsent {
	if d.Store == nil {
		return platform.TrainingConsent{}
	}
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || t.Training == nil {
		return platform.TrainingConsent{}
	}
	return *t.Training
}

// applyTrainingConsent stamps the tenant's standing consent onto an episode that is
// about to run. Called at episode CREATION, never after — see the file comment.
func (d Deps) applyTrainingConsent(ctx context.Context, tenantID string, e *ledger.Episode) {
	c := d.resolveTrainingConsent(ctx, tenantID)
	if !c.Consented || e == nil {
		return
	}
	at := c.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_ = e.GrantConsent(c.By, c.Statement, at)
}

// handleGetTrainingSettings (GET /v1/settings/training) reports the standing decision
// and the exact statement a yes would agree to, so the UI shows the customer the words
// rather than a checkbox label we wrote separately and can drift from.
func (d Deps) handleGetTrainingSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	c := d.resolveTrainingConsent(r.Context(), tenantID)
	writeJSON(w, http.StatusOK, map[string]any{
		"consented":         c.Consented,
		"by":                c.By,
		"at":                c.At,
		"statement":         c.Statement,
		"current_statement": defaultTrainingStatement,
		// Said plainly because it is the thing a customer most reasonably assumes and it
		// is not true: turning this off stops future runs being stamped, and leaves
		// already-recorded episodes exactly as they were recorded.
		"note": "Turning this off applies to future runs. Episodes already recorded under consent are " +
			"not relabelled — ask us to delete them if that is what you want.",
	})
}

// handlePutTrainingSettings (PUT /v1/settings/training) records the decision.
//
// A yes REQUIRES a named human. An unattributed consent is not a consent anybody can
// stand behind later, and it is the same rule the §18.4 HITL acts already enforce.
func (d Deps) handlePutTrainingSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Consented bool   `json:"consented"`
		By        string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	by := strings.TrimSpace(body.By)
	if body.Consented && by == "" {
		writeJSON(w, http.StatusBadRequest, errBody("consent needs a named person: send `by`"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if body.Consented {
		t.Training = &platform.TrainingConsent{
			Consented: true, By: by, At: time.Now().UTC(),
			Statement: defaultTrainingStatement,
		}
	} else {
		// Withdrawal keeps WHO withdrew and WHEN. A revocation that erases itself leaves
		// no way to tell a tenant that declined from one that was never asked, and those
		// are different facts about the same empty field.
		t.Training = &platform.TrainingConsent{Consented: false, By: by, At: time.Now().UTC()}
	}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("training consent updated", "training_consent",
			map[string]any{"tenant_id": tenantID, "consented": body.Consented, "by": by},
			"customer decision on using agent runs to improve the product")
	}
	writeJSON(w, http.StatusOK, map[string]any{"consented": body.Consented, "by": by, "saved": true})
}
