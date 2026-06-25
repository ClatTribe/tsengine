// Package nhidentity is the non-human / AI-agent identity posture — the ACSP (Agentic Cloud Security
// Platform) "identity-aware policy over human, machine, and agentic actions" lens applied to the
// SMB's delegated OAuth grants. The existing SaaS-posture view inventories apps + flags admin scopes;
// this adds the two things that view lacks and the agentic era needs: (1) classify each non-human
// identity as an AI agent / automation / integration, and (2) a least-privilege risk verdict (an AI
// agent or unverified app holding write/admin access is the over-privileged, delegated-permission
// risk the ACSP thesis warns about). Grounded + LLM-free: every verdict derives from the real app
// name + granted scopes, never a guess.
package nhidentity

import (
	"sort"
	"strings"
)

// Grant is the decoupled input (mapped from operate.OAuthGrant by the caller, so this package needn't
// import operate and stays trivially testable).
type Grant struct {
	App      string
	Scopes   []string
	Users    int
	Admin    bool // a directory/admin-control scope was granted
	Verified bool // publisher-verified (false = unknown/unverified)
}

// Identity is a classified non-human identity.
type Identity struct {
	Name       string   `json:"name"`
	Class      string   `json:"class"`     // ai_agent | automation | integration
	Privilege  string   `json:"privilege"` // admin | write | read
	Scopes     []string `json:"scopes"`
	Users      int      `json:"users"`
	Verified   bool     `json:"verified"`
	Risk       string   `json:"risk"` // high | medium | low
	RiskReason string   `json:"risk_reason,omitempty"`
}

// Summary is the portfolio rollup.
type Summary struct {
	Total        int `json:"total"`
	AIAgents     int `json:"ai_agents"`
	Automations  int `json:"automations"`
	WriteOrAdmin int `json:"write_or_admin"`
	Risky        int `json:"risky"` // high-risk identities
}

// aiAgentMarkers / automationMarkers are conservative substrings in the app name. Each is a real,
// recognizable AI/automation product or token — not a broad guess.
var aiAgentMarkers = []string{
	"openai", "anthropic", "claude", "chatgpt", "gpt-", "copilot", "gemini", "perplexity",
	"langchain", "llamaindex", "mcp", "cursor", "huggingface", " ai ", "ai-", "-ai", ".ai", "a.i.", "agent",
}
var automationMarkers = []string{
	"zapier", "make.com", "n8n", "ifttt", "workato", "tray.io", "integromat", "pipedream",
	"automate", "webhook", "bot", "cron", "scheduler",
}

func classOf(app string) string {
	a := " " + strings.ToLower(app) + " "
	for _, m := range aiAgentMarkers {
		if strings.Contains(a, m) {
			return "ai_agent"
		}
	}
	for _, m := range automationMarkers {
		if strings.Contains(a, m) {
			return "automation"
		}
	}
	return "integration"
}

// writeScopeMarkers are scope tokens that imply mutate/write capability (beyond read).
var writeScopeMarkers = []string{"write", "manage", "modify", "admin", "send", ".edit", "full_access", "full", "delete", "create", "update", "readwrite"}

func privilegeOf(g Grant) string {
	if g.Admin {
		return "admin"
	}
	for _, s := range g.Scopes {
		ls := strings.ToLower(s)
		for _, m := range writeScopeMarkers {
			if strings.Contains(ls, m) {
				return "write"
			}
		}
	}
	return "read"
}

// Classify turns the grants into classified identities + a portfolio summary, sorted risk-first.
func Classify(grants []Grant) ([]Identity, Summary) {
	out := make([]Identity, 0, len(grants))
	var sum Summary
	for _, g := range grants {
		id := Identity{
			Name: g.App, Class: classOf(g.App), Privilege: privilegeOf(g),
			Scopes: g.Scopes, Users: g.Users, Verified: g.Verified,
		}
		id.Risk, id.RiskReason = riskOf(id)
		out = append(out, id)

		sum.Total++
		switch id.Class {
		case "ai_agent":
			sum.AIAgents++
		case "automation":
			sum.Automations++
		}
		if id.Privilege == "admin" || id.Privilege == "write" {
			sum.WriteOrAdmin++
		}
		if id.Risk == "high" {
			sum.Risky++
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return riskRank(out[a].Risk) > riskRank(out[b].Risk) })
	return out, sum
}

// riskOf is the least-privilege verdict: an AI agent / automation / unverified app holding
// write-or-admin is the high risk the agentic era introduces. Read-only verified integrations are low.
func riskOf(id Identity) (string, string) {
	writeOrAdmin := id.Privilege == "admin" || id.Privilege == "write"
	nonHumanish := id.Class == "ai_agent" || id.Class == "automation"
	switch {
	case writeOrAdmin && nonHumanish:
		return "high", "an " + label(id.Class) + " holding " + id.Privilege + " access — a delegated permission that can act on your data"
	case writeOrAdmin && !id.Verified:
		return "high", "an unverified app holding " + id.Privilege + " access"
	case writeOrAdmin:
		return "medium", "holds " + id.Privilege + " access"
	case nonHumanish && !id.Verified:
		return "medium", "an unverified " + label(id.Class)
	case nonHumanish:
		return "low", "read-only " + label(id.Class)
	default:
		return "low", ""
	}
}

func label(class string) string {
	switch class {
	case "ai_agent":
		return "AI agent"
	case "automation":
		return "automation"
	default:
		return "integration"
	}
}

func riskRank(r string) int {
	switch r {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
