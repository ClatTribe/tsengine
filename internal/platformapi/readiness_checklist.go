package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/ctoreadiness"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// readiness_checklist.go serves the staged CTO practice checklist, resolved against real tenant state.
//
// The onboarding question this answers is the first one a new customer actually has: "what should a
// company like mine have in place, and what am I missing?" Asking their STAGE is one click and maps
// straight onto the checklist's own tiering — a seed company measured against a Series C bar closes
// the page and never returns. We deliberately do not ask which tools they own: once they connect a
// system we can see it, and a form that asks what we could observe is a form that will be wrong.
//
// Everything here reads stored state (§10). The one thing that cannot be observed — a process fact
// like "is production access gated behind just-in-time elevation" — is answered by a named human and
// recorded as an attestation, never inferred from findings.

type checklistResponse struct {
	Stage    string                `json:"stage"`
	StageSet bool                  `json:"stage_set"`
	Summary  ctoreadiness.Summary  `json:"summary"`
	Items    []ctoreadiness.Result `json:"items"`
	Stages   []map[string]string   `json:"stages"`
}

// handleReadinessChecklist returns the checklist resolved for this tenant.
func (d Deps) handleReadinessChecklist(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	stage := ctoreadiness.Tier(strings.TrimSpace(t.Stage))
	// ?stage= previews another stage without committing to it, so a customer can see what the next
	// round expects before they raise it.
	if q := ctoreadiness.Tier(strings.TrimSpace(r.URL.Query().Get("stage"))); q.Valid() {
		stage = q
	}
	stageSet := stage.Valid()
	if !stageSet {
		stage = ctoreadiness.TierSeed
	}

	in := d.readinessInput(r.Context(), tenantID, t, stage)
	items := ctoreadiness.Assess(in)
	writeJSON(w, http.StatusOK, checklistResponse{
		Stage: string(stage), StageSet: stageSet,
		Summary: ctoreadiness.Summarize(stage, items), Items: items,
		Stages: []map[string]string{
			{"value": "seed", "label": "Seed", "detail": "Pre-revenue to early customers. The basics, done properly."},
			{"value": "series_a", "label": "Series A", "detail": "Real customers and real data. Continuous testing starts here."},
			{"value": "series_b", "label": "Series B", "detail": "Enterprise buyers. Attack paths, SLAs and shadow IT."},
			{"value": "series_c", "label": "Series C+", "detail": "Audited. Drift, perimeter and a formal programme."},
		},
	})
}

// readinessInput gathers the real state the assessment reads.
func (d Deps) readinessInput(ctx context.Context, tenantID string, t platform.Tenant, stage ctoreadiness.Tier) ctoreadiness.Input {
	in := ctoreadiness.Input{
		Stage:        stage,
		AssetTypes:   map[string]bool{},
		ConnKinds:    map[string]bool{},
		Scanned:      map[string]bool{},
		FindingTools: map[string]int{},
		FindingRules: map[string]int{},
		Capabilities: map[string]bool{},
		Attestations: map[string]ctoreadiness.Attestation{},
	}

	assetByID := map[string]platform.Asset{}
	connKindByID := map[string]string{}
	if assets, err := d.Store.ListAssets(ctx, tenantID); err == nil {
		for _, a := range assets {
			in.AssetTypes[string(a.Type)] = true
			assetByID[a.ID] = a
		}
	}
	// ACTIVE connections only. The runner skips assets behind an inactive connection, so counting one
	// here would claim coverage that is not happening — the same false-clean this file guards against.
	if conns, err := d.Store.ListConnections(ctx, tenantID); err == nil {
		for _, c := range conns {
			connKindByID[c.ID] = c.Kind
			if c.Status == platform.ConnActive {
				in.ConnKinds[c.Kind] = true
			}
		}
	}
	// WHAT HAS ACTUALLY BEEN SCANNED, as opposed to merely added. A completed engagement is the
	// evidence that the engine ran against an asset; the asset's type — and the connection that
	// delivered it — are then things we can honestly say were checked. Without this the checklist
	// claimed specific tools had run on assets the engine had never touched.
	if engs, err := d.Store.ListEngagements(ctx, tenantID); err == nil {
		for _, e := range engs {
			if e.CompletedAt.IsZero() {
				continue // still running, or it failed — neither is a completed check
			}
			a, ok := assetByID[e.AssetID]
			if !ok {
				continue // the asset is gone; we cannot say what was scanned
			}
			in.Scanned[string(a.Type)] = true
			if k := connKindByID[a.ConnectionID]; k != "" {
				in.Scanned[k] = true
			}
		}
	}
	if fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{}); err == nil {
		for _, f := range fs {
			in.FindingTools[f.Tool]++
			in.FindingRules[f.RuleID]++
		}
	}

	// Capabilities: the rows where this platform IS the answer, and the question is whether it is on.
	in.Capabilities["appsec.remediation_sla"] = t.SLA != nil
	in.Capabilities["monitor.zeroday_watch"] = t.SLA != nil && len(t.Contacts) > 0
	in.Capabilities["monitor.compliance_program"] = len(t.TargetFrameworks) > 0

	for id, a := range t.ReadinessAttestations {
		in.Attestations[id] = ctoreadiness.Attestation{
			Answered: true, InPlace: a.InPlace, By: a.By, At: a.At, Note: a.Note,
		}
	}
	return in
}

// handleSetStage records the customer's funding stage — the one onboarding question that decides
// which practices they are measured against.
func (d Deps) handleSetStage(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Stage string `json:"stage"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	stage := ctoreadiness.Tier(strings.TrimSpace(body.Stage))
	if !stage.Valid() {
		writeJSON(w, http.StatusBadRequest, errBody("stage must be one of seed, series_a, series_b, series_c"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	t.Stage = string(stage)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stage": string(stage)})
}

// handleAttest records a named human's answer to a practice no scan can observe.
//
// It refuses an attestation against an item we could have OBSERVED. Letting someone assert "yes we
// scan dependencies" when the scanner is right there would turn a measured row into an opinion, and
// the whole point of the four evidence kinds is that they do not collapse into each other.
func (d Deps) handleAttest(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		InPlace bool   `json:"in_place"`
		By      string `json:"by"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if strings.TrimSpace(body.By) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name the person confirming this"))
		return
	}
	var item *ctoreadiness.Item
	for _, it := range ctoreadiness.Items() {
		if it.ID == id {
			c := it
			item = &c
			break
		}
	}
	if item == nil {
		writeJSON(w, http.StatusNotFound, errBody("no such practice"))
		return
	}
	if item.Evidence != ctoreadiness.EvidenceAttested {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this practice is measured, not attested — we check it on every scan, so a typed " +
				"answer would replace evidence with an opinion",
			"reason": "not_attestable",
		})
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
	a := platform.ReadinessAttestation{
		InPlace: body.InPlace, By: strings.TrimSpace(body.By),
		At: time.Now().UTC().Format(time.RFC3339), Note: strings.TrimSpace(body.Note),
	}
	t.ReadinessAttestations[id] = a
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	// Signed into the ledger like every other named-human act (§18.2 inv. 4) — an attestation is a
	// person putting their name to a claim, and that has to be auditable.
	if d.Recorder != nil {
		d.Recorder.Record("readiness practice attested", "readiness",
			map[string]any{"tenant_id": tenantID, "item": id, "in_place": body.InPlace, "by": a.By},
			"CTO checklist attestation")
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": id, "attestation": a})
}
