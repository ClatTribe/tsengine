package platformapi

import (
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The AI-BOM (agentic-SMB spec WRD-1/WRD-2): an inventory of what the autonomous security
// agent can actually TOUCH — every connected system, the scopes it was granted, and a
// least-privilege read/write classification — plus the governance state that bounds it
// (the kill-switch + the human-approval gate tier). It is the "secure the agents
// themselves" artifact: the SMB (and its auditor/insurer) can see, at a glance, the exact
// permission surface of the automation and whether it is least-privilege. Grounded — it
// reflects real Connection.Scopes, never an assertion.

// AIBOM is the agent capability manifest for one tenant.
type AIBOM struct {
	Governance  AIBOMGovernance   `json:"governance"`
	Connections []AIBOMConnection `json:"connections"`
	Summary     AIBOMSummary      `json:"summary"`
}

// AIBOMGovernance is the autonomy boundary the agent operates under.
type AIBOMGovernance struct {
	KillSwitchEngaged bool `json:"kill_switch_engaged"` // Tenant.AgentsHalted — all action frozen
	GateTier          int  `json:"gate_tier"`           // actions at/above this tier need a human (platform.GateTier)
}

// AIBOMConnection is one connected system's capability line.
type AIBOMConnection struct {
	Kind        string   `json:"kind"`
	Account     string   `json:"account,omitempty"`
	Status      string   `json:"status"`
	Scopes      []string `json:"scopes,omitempty"`
	WriteScopes []string `json:"write_scopes,omitempty"` // the subset that can change the system
	Capability  string   `json:"capability"`             // "read-only" | "read-write"
}

// AIBOMSummary is the one-glance posture of the automation's permission surface.
type AIBOMSummary struct {
	Connections  int `json:"connections"`
	WriteCapable int `json:"write_capable"` // the higher-risk surface (a hijacked agent could mutate these)
	ReadOnly     int `json:"read_only"`
}

// readOnlyScope reports whether a scope is unambiguously read-only (an explicit read marker
// always wins, so admin.directory.user.readonly classifies as read, not write).
func readOnlyScope(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "readonly") || strings.Contains(l, "read-only") ||
		strings.HasSuffix(l, ".read") || strings.Contains(l, ":read") ||
		strings.HasPrefix(l, "read:") || strings.HasPrefix(l, "read_")
}

// writeScope reports whether a granted scope can CHANGE the connected system. Heuristic +
// conservative: an explicit read marker means read; otherwise a write/manage/admin verb
// means write. (e.g. GitHub `repo` → write, `read:org` → read; Okta `*.manage` → write,
// `*.read` → read; Workspace `admin.directory.user` → write, `...readonly` → read.)
func writeScope(s string) bool {
	if readOnlyScope(s) {
		return false
	}
	l := strings.ToLower(s)
	for _, w := range []string{"manage", "write", "admin", "lifecycle", "repo", "modify", "delete", "update", ".rw"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// buildAIBOM assembles the manifest from the tenant's governance state + its connections.
func buildAIBOM(t platform.Tenant, conns []platform.Connection) AIBOM {
	bom := AIBOM{
		Governance:  AIBOMGovernance{KillSwitchEngaged: t.AgentsHalted, GateTier: platform.GateTier},
		Connections: []AIBOMConnection{},
		Summary:     AIBOMSummary{Connections: len(conns)},
	}
	for _, c := range conns {
		var writes []string
		for _, s := range c.Scopes {
			if writeScope(s) {
				writes = append(writes, s)
			}
		}
		cap := "read-only"
		if len(writes) > 0 {
			cap = "read-write"
			bom.Summary.WriteCapable++
		} else {
			bom.Summary.ReadOnly++
		}
		bom.Connections = append(bom.Connections, AIBOMConnection{
			Kind: c.Kind, Account: c.Account, Status: c.Status,
			Scopes: c.Scopes, WriteScopes: writes, Capability: cap,
		})
	}
	return bom
}

// handleAIBOM serves the tenant's AI-BOM (agent capability manifest, spec WRD-1). Read-only;
// no secrets — scopes describe permission breadth, never the token itself.
func (d Deps) handleAIBOM(w http.ResponseWriter, r *http.Request, tenantID string) {
	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, buildAIBOM(t, conns))
}
