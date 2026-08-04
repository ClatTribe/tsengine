package platformapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/detectionskill"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// certification.go exposes the Certify half of ADR 0017 — a Detection Skill verdict rendered as
// compliance evidence. Until this endpoint, Certify had no caller: the differentiator ("skills are
// the input, evidence is the output") existed as a data structure the product never invoked.
//
// Computed at READ time, never persisted — the same pattern as annotateSLA. That matters here for a
// specific reason: a certification's control set is DERIVED from the finding's compliance mapping,
// and that mapping can change when the crosswalk is updated. Persisting a certification would freeze
// a control set that later becomes wrong, and an auditor would be reading a stale claim. Deriving it
// on read means it always reflects the current crosswalk, and the skill digest still pins WHICH
// reasoning produced the verdict.
//
// The evidence is UNATTESTED by construction. §18.4: the engine proposes, a named human disposes.
// Attestation is a separate, deliberate human act — this endpoint returns the proposal.

// handleIncidentCertification (GET /v1/incidents/{id}/certification) renders an incident's skill
// verdict as compliance evidence.
func (d Deps) handleIncidentCertification(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")

	incidents, err := d.Store.ListIncidents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var inc *platform.Incident
	for i := range incidents {
		if incidents[i].ID == id {
			inc = &incidents[i]
			break
		}
	}
	if inc == nil {
		writeJSON(w, http.StatusNotFound, errBody("no incident with id "+id))
		return
	}
	// An incident with no skill verdict has nothing to certify. That is an honest 404-shaped state,
	// not an error and not an empty certification — a certification implies an assessment happened.
	if inc.TriageVerdict == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":  "this incident has no Detection Skill verdict, so there is nothing to certify",
			"reason": "not_triaged",
			"hint":   "triage runs when a skill library and an LLM are configured (TSENGINE_SKILLS_DIR)",
		})
		return
	}

	// The evidence universe: the finding that opened the incident. Its compliance mapping is what the
	// certification inherits — Certify never invents a control (ADR 0017).
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		respond(w, nil, err)
		return
	}
	var cited []types.Finding
	for _, f := range findings {
		if f.ID == inc.FindingID {
			cited = append(cited, f)
			break
		}
	}
	if len(cited) == 0 {
		// The verdict named a finding we can no longer read. Refuse rather than certify against
		// nothing — an assessment with no underlying evidence is exactly what §10 forbids.
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  "the finding this verdict rests on is no longer available, so it cannot be certified",
			"reason": "evidence_unavailable",
		})
		return
	}

	verdict, ok := detectionskill.ParseVerdict(inc.TriageVerdict)
	if !ok {
		writeJSON(w, http.StatusConflict, errBody("stored verdict "+inc.TriageVerdict+" is not a recognised Detection Skills outcome"))
		return
	}
	skillName, skillDigest := splitSkillRef(inc.TriageSkill)

	cert, cerr := detectionskill.Certify(detectionskill.Result{
		Verdict:     verdict,
		Rationale:   inc.TriageRationale,
		Evidence:    []string{inc.FindingID},
		SkillName:   skillName,
		SkillDigest: skillDigest,
	}, cited, time.Now().UTC())
	if cerr != nil {
		respond(w, nil, cerr)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id":   inc.ID,
		"certification": cert,
		"summary":       cert.Summary(),
		"frameworks":    cert.Frameworks(),
		"control_count": cert.ControlCount(),
		"attested":      cert.Attested(),
		// Say plainly that this is a proposal. An auditor reading "evidence" must not mistake an
		// un-signed machine assessment for one a person stands behind (§18.4).
		"note": "proposed evidence — unattested. A named human must attest it before it is audit evidence.",
	})
}

// splitSkillRef splits a stored "name@digest" provenance reference. A malformed or absent ref yields
// empty parts rather than a guess — provenance is either known or it is not.
func splitSkillRef(ref string) (name, digest string) {
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == '@' {
			return ref[:i], ref[i+1:]
		}
	}
	return ref, ""
}
