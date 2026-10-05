package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/fixcheck"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// verifyfix.go: POST /v1/findings/{id}/verify-fix — tell a coding agent whether a fix it has written
// for a KNOWN finding is SOUND, before it opens a PR.
//
// WHY THIS IS A "QUESTION" AND NOT AN "ACTION" (and so belongs on the read-only MCP surface). The
// agent supplies the new file content; this computes fixcheck over it (non-trivial, aimed at the cited
// line, parses) and returns the verdict. It commits nothing, opens no PR, and sends no payload at any
// target — it reads the finding's cited location, optionally reads the original file from the
// connected repo, and does pure computation. That is why it can live next to tsmcp's read-only tools:
// a write tool that opened a PR from a chat would bypass the HITL desk, but a verdict over supplied
// content takes no action a human has to approve.
//
// WHAT IT NEVER SAYS. It never says "this change is safe" or "the vulnerability is closed". Soundness
// is not closure — closure needs the customer's runtime and the recorded exploit, verified post-deploy
// (retest + re-attack). A verify tool that returned "safe" on a clean soundness check would be exactly
// the false confidence §0 forbids, sold to another agent. The response carries fixcheck's own scope
// note so the caller cannot read more into it.
func (d Deps) handleVerifyFix(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		Patched  string `json:"patched"`  // the proposed new file content (required)
		Original string `json:"original"` // the current file content (optional — read from the repo if omitted)
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read the request body: "+err.Error()))
		return
	}
	if strings.TrimSpace(body.Patched) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("`patched` (the proposed new file content) is required"))
		return
	}

	// Resolve the finding so the cited-line check has a real location to aim at.
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	var f *types.Finding
	for i := range findings {
		if findings[i].ID == id {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		writeJSON(w, http.StatusNotFound, errBody("no finding with id "+id+" in this workspace"))
		return
	}

	// The cited file is the path half of the finding's endpoint.
	path := f.Endpoint
	if i := strings.LastIndex(path, ":"); i > 0 {
		path = path[:i]
	}

	// Original: use what the caller supplied, else read it from the connected repo (line-numbered, so
	// strip). If neither is available the non-trivial check still runs against "", and the cited-line
	// check reports not_checked rather than guessing — stated honestly, never a pass.
	original := body.Original
	if strings.TrimSpace(original) == "" {
		if src, _ := d.codeSourceFor(r.Context(), tenantID); src != nil {
			if c, rerr := src.ReadFile(r.Context(), path, 0, 0); rerr == nil {
				original = stripLineNumbers(c)
			}
		}
	}

	report := fixcheck.Checks(
		fixcheck.Finding{Endpoint: f.Endpoint},
		[]fixcheck.File{{Path: path, Original: original, Patched: body.Patched}},
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"finding_id": id,
		"path":       path,
		"soundness":  report,
	})
}
