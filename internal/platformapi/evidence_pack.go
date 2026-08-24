package platformapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
)

// handleEvidencePack serves the SIGNED, tamper-evident GRC evidence pack for one framework —
// GET /v1/compliance/{framework}/evidence-pack. This is the auditor-facing artifact the compliance
// pillar points at: posture + gaps + ed25519 attestation over canonical JSON (the same verifier
// that covers the ledger and the scan evidence bundle).
//
// ADR 0031 D2b: Sign/Verify/EvidencePack were implemented and tested with NO production caller,
// while the report route served unsigned Markdown — the flagship deliverable was weaker than its
// own code. This route is the wiring.
//
// HONESTY RULE (§10): an unsigned artifact must NEVER be served from this endpoint. No signer
// configured → 501 naming it; a caller wanting unsigned content uses the report route.
func (d Deps) handleEvidencePack(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	if d.EvidenceSigner == nil {
		writeJSON(w, http.StatusNotImplemented, errBody(
			"evidence-pack signing is not configured on this deployment — set a signing key "+
				"(TSENGINE_SIGNING_KEY path via attest.LoadOrCreate); this endpoint never serves unsigned artifacts"))
		return
	}
	framework := r.PathValue("framework")
	if !grc.IsFramework(framework) {
		// An unknown framework must 404, never render a fabricated empty pack (grounding §10).
		writeJSON(w, http.StatusNotFound, errBody("unknown compliance framework: "+framework))
		return
	}
	pack, err := d.GRC.EvidencePack(r.Context(), tenantID, framework)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	priv, signer, err := d.EvidenceSigner()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("load signing key: "+err.Error()))
		return
	}
	if err := grc.Sign(pack, signer, priv, time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("sign: "+err.Error()))
		return
	}
	// Serve what we signed — deliberately NOT via writeJSON. Its emptyIfNilSlice/fillEmpty pass
	// fills nil slices in the emitted JSON, which would alter the pack AFTER the attestation was
	// computed: every downstream verifier (grc.Verify) would see "hash mismatch — pack altered
	// after signing". An auditor artifact must round-trip byte-faithfully.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pack)
}
