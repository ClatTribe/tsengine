package platformapi

import (
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/registrywatch"
)

// handleRegistryReconcile is the scan-on-push decision API (ADR 0010 Phase 4 wiring). A registry
// connector (ECR/GHCR/Docker Hub) — on a push webhook or a periodic poll — POSTs the registry's
// current images + the digests it last saw; this returns ONLY the images that are new or whose
// digest changed (the scan plan), plus the next-seen state to persist for the following call.
// Stateless by design: the connector owns the seen-state (no server-side store needed), and the
// connector dispatches the actual container scan in the sandbox (the gated half). Deterministic,
// tenant-auth-scoped. Mirrors detect-style reconcile over the registry inventory.
func (d Deps) handleRegistryReconcile(w http.ResponseWriter, r *http.Request, _ string) {
	var body struct {
		Images    []registrywatch.Image `json:"images"`
		Seen      map[string]string     `json:"seen,omitempty"`
		DockerHub *struct {
			Namespace string `json:"namespace"`
			Token     string `json:"token,omitempty"`
		} `json:"dockerhub,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("body must be {images:[{repo,tag,digest}] | dockerhub:{namespace,token}, seen:{ref:digest}}"))
		return
	}
	images := body.Images
	// Built-in source: instead of posting the image list, a caller can give a Docker Hub namespace
	// and we enumerate it live (the credential-gated half — the token is used per-call, not stored).
	if body.DockerHub != nil && body.DockerHub.Namespace != "" {
		listed, err := registrywatch.NewDockerHub(body.DockerHub.Namespace, body.DockerHub.Token).ListImages(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, errBody("dockerhub list: "+err.Error()))
			return
		}
		images = append(images, listed...)
	}
	res := registrywatch.Reconcile(images, body.Seen)
	writeJSON(w, http.StatusOK, map[string]any{
		"to_scan":   res.ToScan, // scan these (new or re-pushed) — pin by repo@digest
		"new":       res.New,
		"updated":   res.Updated,
		"unchanged": res.Unchanged,
		"next_seen": res.NextSeen, // persist + pass back on the next reconcile
	})
}
