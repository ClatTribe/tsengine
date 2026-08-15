package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// assetenv.go records WHERE an asset lives, so the pentester can refuse to attack a live system that
// nobody authorized it to touch.
//
// The scope model already answers "may we touch app.acme.com". It could not answer "is app.acme.com
// your production system or a throwaway copy" — a distinction every buyer at this size raises in
// their vendor security review, usually first.
//
// Stored on Asset.Meta like the data tier, so no store migration is needed. The gating logic lives in
// internal/pentest (environment.go), which is where the safety rules belong; this is only the door.
//
// The default matters more than the feature: an asset nobody has classified reads as PRODUCTION, and
// the label says so out loud rather than showing a blank that reads as "fine".

// envKey is where the environment lives on the asset.
const envKey = "environment"

// AssetEnvironment reads an asset's recorded environment. Absent → EnvUnknown, which the pentest
// gate treats as production.
func AssetEnvironment(a platform.Asset) pentest.Environment {
	return pentest.Environment(strings.TrimSpace(a.Meta[envKey]))
}

// handleSetAssetEnvironment records whether an asset is production, staging or development.
func (d Deps) handleSetAssetEnvironment(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		Environment string `json:"environment"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	env := pentest.Environment(strings.TrimSpace(body.Environment))
	if !env.Valid() {
		// "unknown" is deliberately not settable — it is a state the system infers from silence, not
		// one a person chooses. Offering it would let someone mark an asset unclassified on purpose,
		// which reads as a decision when it is the absence of one.
		writeJSON(w, http.StatusBadRequest, errBody("environment must be production, staging, or development"))
		return
	}

	assets, err := d.Store.ListAssets(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var found *platform.Asset
	for i := range assets {
		if assets[i].ID == id {
			found = &assets[i]
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, errBody("asset not found"))
		return
	}
	if found.Meta == nil {
		found.Meta = map[string]string{}
	}
	found.Meta[envKey] = string(env)
	if err := d.Store.PutAsset(r.Context(), *found); err != nil {
		respond(w, nil, err)
		return
	}
	// Ledger-recorded: classifying a system as non-production widens what may be done to it, so it is
	// a governance decision and not a display preference.
	if d.Recorder != nil {
		d.Recorder.Record("asset environment set", "asset_environment",
			map[string]any{"tenant_id": tenantID, "asset": id, "environment": string(env)},
			"scope classification")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset": id, "environment": string(env), "label": env.Label(),
		"gated_as_production": env.IsProduction(),
	})
}

// environmentSuggestion proposes a value from the target's name, for PRE-FILLING the control.
//
// It is a suggestion and is labelled as one. "staging.acme.com" is probably staging;
// "staging-mirror.prod.acme.com" is probably not, and the guesser returns unknown for exactly that
// case rather than resolving it — see pentest.Guess.
func environmentSuggestion(a platform.Asset) string {
	return string(pentest.Guess(a.Target))
}
