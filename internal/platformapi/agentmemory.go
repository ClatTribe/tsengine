package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/agentmemory"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

const (
	maxAgentNotes   = 50
	maxAgentNoteLen = 500
)

// agentMemory assembles what the AI engineer is told about this tenant. Best-effort: a store read that
// fails leaves that part out rather than failing the run — the memory is context, and the run's findings
// are what matter.
func (d Deps) agentMemory(ctx context.Context, tenantID string, assets []platform.Asset) agentmemory.Memory {
	in := agentmemory.Inputs{Assets: assets, Now: time.Now().UTC()}
	if t, err := d.Store.GetTenant(ctx, tenantID); err == nil {
		in.Tenant = t
	}
	if in.Assets == nil {
		in.Assets, _ = d.Store.ListAssets(ctx, tenantID)
	}
	in.Ignores, _ = d.Store.ListIgnoreRules(ctx, tenantID)
	in.Actions, _ = d.Store.ListActions(ctx, tenantID)
	in.Feedback, _ = d.Store.ListFeedback(ctx, tenantID)
	return agentmemory.Build(in)
}

// handleGetAgentMemory returns exactly what the AI engineer is told — the same builder feeds the prompt.
func (d Deps) handleGetAgentMemory(w http.ResponseWriter, r *http.Request, tenantID string) {
	writeJSON(w, http.StatusOK, d.agentMemory(r.Context(), tenantID, nil))
}

// handleAddAgentNote stores something a person tells the AI engineer. The author is the signed-in person.
func (d Deps) handleAddAgentNote(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Text string `json:"text"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body)
	text := strings.Join(strings.Fields(body.Text), " ")
	if text == "" {
		writeJSON(w, http.StatusBadRequest, errCode("a note needs some text", "empty_note"))
		return
	}
	if len(text) > maxAgentNoteLen {
		writeJSON(w, http.StatusBadRequest, errCode("keep a note under 500 characters — it is read on every run", "note_too_long"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if len(t.AgentNotes) >= maxAgentNotes {
		writeJSON(w, http.StatusBadRequest, errCode("there are already 50 notes; remove one first", "too_many_notes"))
		return
	}
	by := "platform"
	if u, ok := d.actingUser(r); ok {
		by = u.Email
	}
	n := platform.AgentNote{ID: d.newID("note"), Text: text, By: by, At: time.Now().UTC()}
	t.AgentNotes = append(t.AgentNotes, n)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("agent note added", "agent_memory", map[string]any{"tenant_id": tenantID, "note_id": n.ID, "by": by}, "the AI engineer was told: "+text)
	}
	writeJSON(w, http.StatusOK, n)
}

func (d Deps) handleDeleteAgentNote(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	id := r.PathValue("id")
	kept := t.AgentNotes[:0:0]
	found := false
	for _, n := range t.AgentNotes {
		if n.ID == id {
			found = true
			continue
		}
		kept = append(kept, n)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("note not found"))
		return
	}
	t.AgentNotes = kept
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("agent note removed", "agent_memory", map[string]any{"tenant_id": tenantID, "note_id": id}, "agent note removed")
	}
	w.WriteHeader(http.StatusNoContent)
}
