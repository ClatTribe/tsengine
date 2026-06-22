package platformapi

import (
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/postman"
)

// handlePostmanImport imports a Postman collection (v2.x) into the api asset's endpoint inventory
// — the api integration for teams whose API surface lives in Postman rather than a served OpenAPI
// spec. It flattens the collection's requests into "METHOD url" operations (the same shape the api
// PlanFanout consumes), which the caller uses to scope/seed an api asset. Stateless + grounded:
// only requests present in the collection become endpoints; nothing is fetched or guessed.
func (d Deps) handlePostmanImport(w http.ResponseWriter, r *http.Request, _ string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20)) // collections can be large
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read body"))
		return
	}
	col, err := postman.Endpoints(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	endpoints := col.Operations
	if endpoints == nil {
		endpoints = []string{} // never serialize a nil slice as null
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":      col.Name,
		"count":     len(endpoints),
		"endpoints": endpoints,
	})
}
