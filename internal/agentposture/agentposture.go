// Package agentposture is AI-AGENT ESTATE POSTURE — the "which AI agents run in this org, and are
// they governed?" capability. Employee-run coding agents (Claude Code, Cursor, Codex, Cline) and the
// MCP servers they load are an asset class the engine could not see at all: nhidentity classifies
// DELEGATED SaaS OAuth grants, sspm covers SaaS config, deviceposture covers endpoints — none of them
// observe the agents themselves. That is the shadow-AI blind spot.
//
// Input is a normalized snapshot, decoupled from any collector so this package stays trivially
// testable. It maps cleanly onto the unified schema of Uber's ADR Sensor (Apache-2.0, github.com/
// uber/ADR — the leading OSS agent-telemetry collector, MLSys 2026, production-deployed), which is the
// intended live source; a posted snapshot works today with no collector at all, mirroring how osint /
// tprm / deviceposture shipped.
//
// SCOPE — and why this is not a §13 violation. This package assesses POSTURE: inventory and
// configuration facts (is this agent sanctioned? is that MCP server pinned? does it auto-approve? did
// it touch a credential path?). It deliberately does NOT attempt behavioural detection of a
// compromised or prompt-injected session — that is a real detector, OSS already exists for it (ADR's
// dual-agent detector), and building our own would be exactly the in-house engine §13 forbids. The
// line is the same one sspm/deviceposture draw: configuration posture here, detection wrapped later.
//
// TRUST BOUNDARY. Agent telemetry contains model transcripts and tool OUTPUT — text that is
// adversarial by construction, since prompt injection is one of the things it may carry. Two rules
// hold throughout:
//
//  1. Every check matches on STRUCTURED fields only — tool names, filesystem paths, MCP server
//     identity, host names. Nothing here reasons over free-form transcript, so injected prose has no
//     control-flow effect on a verdict.
//  2. Any snapshot-supplied string that reaches a finding is sanitized and truncated (see safe), so a
//     crafted server name cannot smuggle markup or a wall of instructions into an analyst's screen or
//     into a downstream L2 prompt.
//
// Grounded (§10) + LLM-free: every finding cites a real recorded attribute, and a fully-governed agent
// estate yields ZERO findings. Absent data never invents risk — an unstated field is unknown, not bad.
package agentposture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// MCPServer is one Model Context Protocol server an agent loads. An MCP server is executable
// third-party capability inside the agent's trust boundary, so its provenance is the supply-chain
// question — the same class safechain guards at install time.
type MCPServer struct {
	Name     string   `json:"name"`
	Source   string   `json:"source,omitempty"`   // registry ref, URL, or local path
	Pinned   bool     `json:"pinned,omitempty"`   // version/digest pinned (a floating ref can change under you)
	Verified bool     `json:"verified,omitempty"` // known/approved publisher
	Scopes   []string `json:"scopes,omitempty"`   // capabilities granted to it
}

// ToolUse is an observed tool invocation, reduced to structured fields. Target is a path or host —
// never a transcript excerpt.
type ToolUse struct {
	Tool   string `json:"tool"`             // e.g. Bash, Read, Write, WebFetch
	Target string `json:"target,omitempty"` // path or host touched
	Count  int    `json:"count,omitempty"`
}

// Autonomy levels an agent may run at.
const (
	AutonomySupervised  = "supervised"   // a human approves consequential actions
	AutonomyAutoApprove = "auto-approve" // the agent acts without per-action approval
)

// Agent is one AI agent observed in the estate. Every field is a stated fact from the collector or the
// team's own inventory — never inferred.
type Agent struct {
	Name       string      `json:"name"` // claude-code | cursor | codex | cline | ...
	Version    string      `json:"version,omitempty"`
	User       string      `json:"user,omitempty"` // operator email
	Host       string      `json:"host,omitempty"`
	Model      string      `json:"model,omitempty"`
	Sanctioned bool        `json:"sanctioned,omitempty"` // on the org's approved-tool list
	Autonomy   string      `json:"autonomy,omitempty"`
	Sessions   int         `json:"sessions,omitempty"`
	LastSeen   time.Time   `json:"last_seen,omitempty"`
	MCPServers []MCPServer `json:"mcp_servers,omitempty"`
	ToolUse    []ToolUse   `json:"tool_use,omitempty"`
}

// Snapshot is the posted agent-estate inventory.
type Snapshot struct {
	Agents []Agent `json:"agents"`
}

// Assess turns an agent-estate snapshot into grounded posture findings.
func Assess(s Snapshot, now time.Time) []types.Finding {
	var out []types.Finding
	for i, a := range s.Agents {
		// An agent we cannot NAME is not assessed.
		//
		// Every finding here identifies its subject in the title and description, so a nameless agent
		// produced "Unsanctioned AI agent in use: " — a HIGH-severity finding, carrying SOC 2 CC1.4 and
		// ISO 42001 mappings into an auditor's evidence pack, about nothing anyone could act on. An
		// export whose field names we do not recognise is unreadable, not a clean estate, and the
		// caller is told which agents were skipped rather than left to read silence as coverage.
		if strings.TrimSpace(a.Name) == "" {
			continue
		}
		out = append(out, assessAgent(a, i, now)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func assessAgent(a Agent, idx int, now time.Time) []types.Finding {
	var out []types.Finding
	ep := endpointFor(a)
	n := 0
	add := func(rule string, sev types.Severity, title, desc string, c types.Compliance) {
		n++
		out = append(out, types.Finding{
			ID: fmt.Sprintf("agent-%03d-%d", idx+1, n), RuleID: rule, Tool: "agentposture",
			Severity: sev, Title: title, Endpoint: ep, Description: desc,
			DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: &c,
		})
	}

	// SHADOW AI. An agent nobody approved is the whole category: it reads source and secrets with the
	// developer's own access, and no policy, logging, or review applies to it.
	if !a.Sanctioned {
		add("agentposture::unsanctioned-agent", types.SeverityHigh,
			"Unsanctioned AI agent in use: "+safe(a.Name, 60),
			fmt.Sprintf("%s is running in the estate but is not on the approved-tool list. It operates with %s access to code and credentials, outside any approved-use policy or review.",
				safe(a.Name, 60), nz(safe(a.User, 60), "a developer's")),
			types.Compliance{
				ISO42001: []string{"A.6.2.2"}, NISTAIRMF: []string{"GOVERN-1.1", "MAP-1.1"},
				EUAIAct: []string{"Art. 26"}, SOC2: []string{"CC1.4", "CC6.1"}, CISv8: []string{"2.1"},
			})
	}

	// NO HUMAN IN THE LOOP. Auto-approve turns every downstream weakness (a poisoned MCP server, an
	// injected instruction in a fetched page) into an executed action with no gate.
	if strings.EqualFold(a.Autonomy, AutonomyAutoApprove) {
		add("agentposture::auto-approve", types.SeverityHigh,
			"AI agent runs without per-action approval: "+safe(a.Name, 60),
			fmt.Sprintf("%s is configured to act without human approval. Any successful prompt injection or compromised tool becomes an executed action rather than a prompt a person can refuse.", safe(a.Name, 60)),
			types.Compliance{
				ISO42001: []string{"A.9.2"}, NISTAIRMF: []string{"MANAGE-2.1", "GOVERN-3.2"},
				EUAIAct: []string{"Art. 14"}, SOC2: []string{"CC5.2"},
			})
	}

	// MODEL GOVERNANCE. You cannot govern what you cannot name — an unrecorded model means no record
	// of what processed the code and data this agent touched.
	if strings.TrimSpace(a.Model) == "" {
		add("agentposture::unknown-model", types.SeverityMedium,
			"AI agent with no recorded model: "+safe(a.Name, 60),
			fmt.Sprintf("No model is recorded for %s, so there is no record of which system processed the code and data it accessed — the AI-inventory requirement cannot be evidenced for it.", safe(a.Name, 60)),
			types.Compliance{
				ISO42001: []string{"A.4.2"}, NISTAIRMF: []string{"MAP-2.1"}, EUAIAct: []string{"Art. 12"},
			})
	}

	out = append(out, assessMCP(a, idx, ep, &n, now)...)
	out = append(out, assessToolUse(a, idx, ep, &n, now)...)
	return out
}

// assessMCP covers the agent's loaded MCP servers — executable third-party capability inside the
// agent's trust boundary.
func assessMCP(a Agent, idx int, ep string, n *int, now time.Time) []types.Finding {
	var out []types.Finding
	add := func(rule string, sev types.Severity, title, desc string, c types.Compliance) {
		*n++
		out = append(out, types.Finding{
			ID: fmt.Sprintf("agent-%03d-%d", idx+1, *n), RuleID: rule, Tool: "agentposture",
			Severity: sev, Title: title, Endpoint: ep, Description: desc,
			DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: &c,
		})
	}
	for _, m := range a.MCPServers {
		name := safe(m.Name, 60)
		// Unpinned is the supply-chain risk: a floating ref can change under you between runs, so what
		// was reviewed is not necessarily what executes. Same class safechain guards at install time.
		if !m.Pinned {
			add("agentposture::unpinned-mcp", types.SeverityHigh,
				"Unpinned MCP server loaded by "+safe(a.Name, 40)+": "+name,
				fmt.Sprintf("MCP server %q (%s) is not pinned to a version or digest. Its code can change between runs, so what was reviewed is not necessarily what executes inside the agent's trust boundary.",
					name, nz(safe(m.Source, 80), "source unrecorded")),
				types.Compliance{
					ISO42001: []string{"A.10.3"}, NISTAIRMF: []string{"MANAGE-3.1"},
					SOC2: []string{"CC9.2"}, CISv8: []string{"2.4"}, NIST80053: []string{"SR-3"},
				})
		}
		if !m.Verified {
			add("agentposture::unverified-mcp", types.SeverityMedium,
				"Unverified MCP publisher for "+name,
				fmt.Sprintf("MCP server %q comes from an unverified publisher (%s). It runs with the agent's own access to the developer's code and credentials.",
					name, nz(safe(m.Source, 80), "source unrecorded")),
				types.Compliance{
					ISO42001: []string{"A.10.3"}, NISTAIRMF: []string{"MANAGE-3.1"}, SOC2: []string{"CC9.2"},
				})
		}
	}
	return out
}

// assessToolUse covers what the agent actually touched. Structured targets only — never transcript.
func assessToolUse(a Agent, idx int, ep string, n *int, now time.Time) []types.Finding {
	var out []types.Finding
	add := func(rule string, sev types.Severity, title, desc string, c types.Compliance) {
		*n++
		out = append(out, types.Finding{
			ID: fmt.Sprintf("agent-%03d-%d", idx+1, *n), RuleID: rule, Tool: "agentposture",
			Severity: sev, Title: title, Endpoint: ep, Description: desc,
			DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: &c,
		})
	}
	var secrets, destructive []string
	for _, t := range a.ToolUse {
		if p := matchAny(t.Target, secretPaths); p != "" {
			secrets = appendUnique(secrets, safe(t.Target, 100))
		}
		if p := matchAny(t.Tool+" "+t.Target, destructiveOps); p != "" {
			destructive = appendUnique(destructive, safe(p, 40))
		}
	}
	if len(secrets) > 0 {
		add("agentposture::secret-path-access", types.SeverityCritical,
			"AI agent read credential material: "+safe(a.Name, 60),
			fmt.Sprintf("%s accessed credential paths (%s). Anything the agent reads may be sent to the model provider and may appear in later completions — treat these secrets as disclosed and rotate them.",
				safe(a.Name, 60), strings.Join(secrets, ", ")),
			types.Compliance{
				ISO42001: []string{"A.8.3"}, NISTAIRMF: []string{"MANAGE-2.2"}, EUAIAct: []string{"Art. 10"},
				SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"AC-6", "SC-28"},
				CISv8: []string{"3.3"},
			})
	}
	if len(destructive) > 0 {
		add("agentposture::destructive-tool-use", types.SeverityHigh,
			"AI agent performed destructive operations: "+safe(a.Name, 60),
			fmt.Sprintf("%s executed destructive operations (%s). Confirm each was intended; an agent acting on injected instructions reaches exactly these commands.",
				safe(a.Name, 60), strings.Join(destructive, ", ")),
			types.Compliance{
				ISO42001: []string{"A.9.2"}, NISTAIRMF: []string{"MANAGE-2.1"}, EUAIAct: []string{"Art. 14"},
				SOC2: []string{"CC8.1"}, NIST80053: []string{"CM-3"},
			})
	}
	return out
}

// secretPaths are credential-bearing locations. Deliberately specific: a broad "secret" substring
// would fire on ordinary source files and make the check useless.
var secretPaths = []string{
	".env", ".aws/credentials", ".ssh/id_", "id_rsa", "id_ed25519", ".kube/config",
	".npmrc", ".pypirc", ".netrc", ".docker/config.json", "service-account", "credentials.json",
	".pem", ".p12", "gcloud/application_default_credentials",
}

// destructiveOps are irreversible or high-blast-radius operations.
var destructiveOps = []string{
	"rm -rf", "rm -fr", "git push --force", "git push -f", "drop table", "drop database",
	"truncate table", "kubectl delete", "terraform destroy", "dd if=", "mkfs", "shutdown",
}

func matchAny(hay string, needles []string) string {
	h := strings.ToLower(hay)
	for _, n := range needles {
		if strings.Contains(h, n) {
			return n
		}
	}
	return ""
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func endpointFor(a Agent) string {
	who := nz(safe(a.User, 60), nz(safe(a.Host, 60), "unknown"))
	return "agent:" + nz(safe(a.Name, 60), "unknown") + "@" + who
}

// safe sanitizes a snapshot-supplied string before it reaches a finding. Agent telemetry carries
// adversarial text by construction (prompt injection is among the things it may contain), so a
// crafted MCP server name must not be able to smuggle markup, control characters, or a wall of
// instructions into an analyst's screen or a downstream L2 prompt.
func safe(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f: // control characters
			return -1
		case r == '<' || r == '>' || r == '`': // markup / fence injection
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ") // collapse whitespace runs
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

// Unnamed reports how many agents in the snapshot carry no name, so the ingest can say what it
// skipped. Assess drops them (a finding about an agent nobody can identify is unactionable), and
// silence about that would read as "we looked at your whole estate".
func Unnamed(s Snapshot) int {
	n := 0
	for _, a := range s.Agents {
		if strings.TrimSpace(a.Name) == "" {
			n++
		}
	}
	return n
}
