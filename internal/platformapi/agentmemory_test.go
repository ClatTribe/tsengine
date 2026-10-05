package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/agentmemory"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A note's author is the signed-in person; the memory endpoint returns exactly what the agent is told,
// including the note; removing it removes it from the agent's memory too.
func TestAgentMemory_NotesRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "ana@acme.com", Role: platform.RoleMember})
	_ = st.PutSession(ctx, platform.Session{Token: "s1", UserID: "u1", TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)})
	d := Deps{Store: st}
	req := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer s1")
		if i := strings.LastIndex(path, "/notes/"); i >= 0 {
			r.SetPathValue("id", path[i+len("/notes/"):])
		}
		w := httptest.NewRecorder()
		switch method {
		case "POST":
			d.handleAddAgentNote(w, r, "t1")
		case "DELETE":
			d.handleDeleteAgentNote(w, r, "t1")
		default:
			d.handleGetAgentMemory(w, r, "t1")
		}
		return w
	}
	if w := req("POST", "/v1/agent-memory/notes", `{"text":"   "}`); w.Code != http.StatusBadRequest {
		t.Errorf("an empty note must be refused: %d", w.Code)
	}
	var n platform.AgentNote
	_ = json.Unmarshal(req("POST", "/v1/agent-memory/notes", `{"text":"payments-api deploys only on Tuesdays","by":"someone-else"}`).Body.Bytes(), &n)
	if n.By != "ana@acme.com" {
		t.Errorf("the author must be the session user, never a typed name: %q", n.By)
	}
	var m agentmemory.Memory
	_ = json.Unmarshal(req("GET", "/v1/agent-memory", "").Body.Bytes(), &m)
	if len(m.Lines) != 1 || m.Lines[0].NoteID != n.ID {
		t.Fatalf("memory: %+v", m)
	}
	if w := req("DELETE", "/v1/agent-memory/notes/"+n.ID, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", w.Code)
	}
	_ = json.Unmarshal(req("GET", "/v1/agent-memory", "").Body.Bytes(), &m)
	if len(m.Lines) != 0 {
		t.Errorf("a removed note must leave the agent's memory: %+v", m.Lines)
	}
}

type promptCapture struct{ system string }

func (p *promptCapture) Generate(_ context.Context, system string, _ []l2.Message, _ []l2.ToolSchema) (l2.Response, error) {
	p.system = system
	return l2.Response{Text: "done", StopReason: "end_turn"}, nil
}
func (p *promptCapture) Model() string      { return "capture" }
func (p *promptCapture) ContextWindow() int { return 200000 }

// WIRING, not just the builder: a real L2 run's system prompt carries the customer's memory. The builder
// being tested in isolation would pass with the run never seeing it — the built-but-unwired shape.
func TestAgentMemory_ReachesARealRun(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", AgentNotes: []platform.AgentNote{{ID: "n1", Text: "payments-api deploys only on Tuesdays"}}})
	d := Deps{Store: st}
	pc := &promptCapture{}
	_, _ = d.runEstateAgent(ctx, "t1", pc, types.Asset{Type: "web_application", Target: "https://x"}, nil, nil, 1)
	if !strings.Contains(pc.system, "payments-api deploys only on Tuesdays") {
		t.Fatalf("the run's prompt does not carry the customer's memory:\n%.600s", pc.system)
	}
}
