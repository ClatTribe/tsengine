package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/recertify"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// recertify_api.go is the door to the periodic access review (SOC 2 CC6.2/CC6.3).
//
// The campaign is rebuilt from the tenant's CURRENT identity findings on every read, and the
// decisions are stored separately and merged back on. That is deliberate: an access review is about
// who has access NOW, so a campaign frozen at open-time would send a reviewer to confirm access for
// someone who was deprovisioned last week, and would miss the person who was granted admin
// yesterday. Rebuilding keeps the question current; keeping the decisions makes the review durable.
//
// A decision already recorded for someone who has since dropped off the list simply stops appearing —
// their access is no longer flagged, so there is nothing to attest to.
//
// Nothing here revokes anything. A "revoke" verdict is recorded and surfaced; acting on it goes
// through remediate + the approval desk like every other change (§18.2 inv. 3).

// recertDecisionsKey namespaces stored review decisions on the tenant.
const recertDecisionsKey = "recert:"

type recertResponse struct {
	Progress   recertify.Progress   `json:"progress"`
	Identities []recertify.Identity `json:"identities"`
	// Detail states what the numbers mean, because "0 of 0" and "12 of 12" both read as complete to
	// someone skimming, and only one of them is.
	Detail string `json:"detail"`
	// Revocations is what the reviewer decided to remove — surfaced so the UI can offer to raise the
	// removals, which still go through the approval desk.
	Revocations []recertify.Identity `json:"revocations,omitempty"`
}

// handleRecertify returns the current access review.
func (d Deps) handleRecertify(w http.ResponseWriter, r *http.Request, tenantID string) {
	c, err := d.buildRecertCampaign(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	p := recertify.Summarize(c)
	writeJSON(w, http.StatusOK, recertResponse{
		Progress: p, Identities: c.Identities,
		Revocations: recertify.Revocations(c),
		Detail:      recertDetail(p),
	})
}

// recertDetail says what the state actually means. The empty case is the one that matters: an
// auditor reading "complete" must never be reading a review that examined nobody.
func recertDetail(p recertify.Progress) string {
	switch {
	case p.Total == 0:
		return "No accounts are currently flagged for review. This is not a completed access review — " +
			"connect an identity provider so we can see who has access."
	case p.Complete:
		return "Every flagged account has been reviewed. " + plural(p.Keep, "was kept", "were kept") +
			", " + plural(p.Revoke, "marked for removal", "marked for removal") + "."
	default:
		return plural(p.Pending, "account still needs", "accounts still need") + " a decision. " +
			"The review is not complete until every one has been answered."
	}
}

// handleRecertifyDecide records one reviewer's verdict on one account.
func (d Deps) handleRecertifyDecide(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Subject  string `json:"subject"`
		Decision string `json:"decision"` // keep | revoke
		By       string `json:"by"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	dec := recertify.Decision(strings.TrimSpace(body.Decision))
	if !dec.Valid() {
		writeJSON(w, http.StatusBadRequest, errBody(`decision must be "keep" or "revoke"`))
		return
	}
	if strings.TrimSpace(body.By) == "" {
		// An access review is only evidence if a named person stood behind it. This refusal is the
		// difference between an audit artifact and a log line.
		writeJSON(w, http.StatusBadRequest, errBody("name the person reviewing this access"))
		return
	}

	c, err := d.buildRecertCampaign(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if !recertify.Decide(&c, strings.TrimSpace(body.Subject), dec, body.By, body.Note, time.Now()) {
		writeJSON(w, http.StatusNotFound, errBody("that account is not in the current review"))
		return
	}

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if t.ReadinessAttestations == nil {
		t.ReadinessAttestations = map[string]platform.ReadinessAttestation{}
	}
	// Stored as an attestation because that is exactly what it is: a named human answering something
	// no scan can decide. Reusing the type keeps one notion of "a person said so" in the model.
	t.ReadinessAttestations[recertDecisionsKey+strings.TrimSpace(body.Subject)] = platform.ReadinessAttestation{
		InPlace: dec == recertify.DecisionKeep,
		By:      strings.TrimSpace(body.By),
		At:      time.Now().UTC().Format(time.RFC3339),
		Note:    strings.TrimSpace(body.Note),
	}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("access reviewed", "access_recertification",
			map[string]any{"tenant_id": tenantID, "subject": body.Subject,
				"decision": string(dec), "by": strings.TrimSpace(body.By)},
			"SOC 2 CC6.2/CC6.3 periodic access review")
	}

	c2, _ := d.buildRecertCampaign(r.Context(), tenantID)
	p := recertify.Summarize(c2)
	writeJSON(w, http.StatusOK, recertResponse{
		Progress: p, Identities: c2.Identities,
		Revocations: recertify.Revocations(c2), Detail: recertDetail(p),
	})
}

// buildRecertCampaign rebuilds the campaign from current findings and replays stored decisions.
func (d Deps) buildRecertCampaign(ctx context.Context, tenantID string) (recertify.Campaign, error) {
	fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return recertify.Campaign{}, err
	}
	c, _ := recertify.Build("recert-"+tenantID, tenantID, fs, time.Now())

	t, terr := d.Store.GetTenant(ctx, tenantID)
	if terr != nil {
		return c, nil // no stored decisions is a valid state — every row is simply pending
	}
	for k, a := range t.ReadinessAttestations {
		if !strings.HasPrefix(k, recertDecisionsKey) {
			continue
		}
		subject := strings.TrimPrefix(k, recertDecisionsKey)
		dec := recertify.DecisionRevoke
		if a.InPlace {
			dec = recertify.DecisionKeep
		}
		at, _ := time.Parse(time.RFC3339, a.At)
		// A decision for someone no longer flagged just does not apply — Decide returns false and we
		// move on. Their access is no longer in question, so there is nothing to attest to.
		recertify.Decide(&c, subject, dec, a.By, a.Note, at)
	}
	return c, nil
}
