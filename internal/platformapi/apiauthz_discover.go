package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/apiauthz"
)

// handleAuthzDiscover (POST /v1/apiauthz/discover) is the API BOLA/BFLA discovery agent — the API-asset
// gap (competitor parity with AI-driven API security, e.g. Akto). Given the API's KNOWN operations it
// asks the LLM to PROPOSE additional candidate operations likely to carry an authz bypass; the owner adds
// the good ones to their BOLA/BFLA test config, and the deterministic differential test (apiauthz.Evaluate,
// active+consent-gated) is what CONFIRMS a real bypass. The model only widens discovery → no false
// positives (§10), same safety model as the pentest D-agent. Gated on an LLM; no LLM → 400.
func (d Deps) handleAuthzDiscover(w http.ResponseWriter, r *http.Request, tenantID string) {
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("API authz discovery needs an LLM: configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	var body struct {
		Operations []struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Class  string `json:"class"`
			Marker string `json:"marker"`
		} `json:"operations"`
	}
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	_ = json.Unmarshal(raw, &body)
	known := make([]apiauthz.Operation, 0, len(body.Operations))
	for _, o := range body.Operations {
		known = append(known, apiauthz.Operation{Method: o.Method, URL: o.URL, Class: apiauthz.Class(o.Class), Marker: o.Marker})
	}
	props, err := apiauthz.ProposeOperations(r.Context(), llm, known, 12)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("api authz discovered", "l2-apiauthz",
			map[string]any{"tenant_id": tenantID, "known": len(known), "proposed": len(props)}, "API BOLA/BFLA discovery")
	}
	if props == nil {
		props = []apiauthz.Operation{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"proposed": props, "count": len(props),
		"note": "Candidate authz tests — add the relevant ones to the asset's BOLA/BFLA test config; the live differential test confirms a real bypass.",
	})
}
