package bench

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// integration_agent.go is the LLM AGENT-LAYER benchmark for the AI Security Engineer — the
// twin of the deterministic integration-coverage bench (integration.go), for the two
// open-ended agents the generalist delegates depth to: the AI Cloud Engineer (cloudagent,
// over the IAM graph) and the AI Code Engineer (codeagent, over source). It scores each on a
// planted estate:
//   - recall    — the real issues the agent CONFIRMED
//   - grounding — invented issues / false confirmations (must be 0, §10)
// The agent needs a brain: cloudengine.LLMFromEnv resolves the dev PROXY (frontier Claude)
// or a local Ollama — so this runs credential-free (no cloud key) yet against a real model.

// AgentResult scores one agent's run on a planted estate.
type AgentResult struct {
	Agent     string   `json:"agent"`
	Planted   int      `json:"planted"`
	Confirmed int      `json:"confirmed"`
	Missed    []string `json:"missed,omitempty"`
	Invented  []string `json:"invented,omitempty"` // grounding violations — issues with no real basis
	Calls     int      `json:"tool_calls"`
}

// Recall is confirmed / planted (1.0 when nothing planted).
func (r AgentResult) Recall() float64 {
	if r.Planted == 0 {
		return 1
	}
	return float64(r.Confirmed) / float64(r.Planted)
}

// Pass is full recall with zero grounding violations.
func (r AgentResult) Pass() bool { return len(r.Missed) == 0 && len(r.Invented) == 0 }

// benchCloudAgent runs the AI Cloud Engineer over a synthetic account with real
// internet→jewel paths + config-bad-but-inert decoys, and scores real-target recall +
// grounding (an issue whose target isn't a real graph node is invented).
func benchCloudAgent(ctx context.Context, llm cloudengine.LLM) AgentResult {
	scn := cloudengine.Generate(42, 2, 2, true)
	r := AgentResult{Agent: "AI Cloud Engineer (cloudagent)", Planted: len(scn.RealTargets)}
	rep, err := cloudagent.Investigate(ctx, llm, &cloudagent.Context{Snap: scn.Snapshot, Prowler: scn.Prowler, MaxHyp: 20},
		cloudagent.Options{MaxIters: 24, MaxHyp: 20})
	if err != nil || rep == nil {
		r.Missed = append(r.Missed, scn.RealTargets...)
		return r
	}
	r.Calls = rep.Calls
	txt := func(is cloudagent.Issue) string {
		return strings.ToLower(is.Target + " " + is.TargetName + " " + strings.Join(is.Path, " "))
	}
	for _, tgt := range scn.RealTargets {
		hit := false
		for _, is := range rep.Issues {
			if strings.Contains(txt(is), strings.ToLower(tgt)) {
				hit = true
				break
			}
		}
		if hit {
			r.Confirmed++
		} else {
			r.Missed = append(r.Missed, tgt)
		}
	}
	for _, is := range rep.Issues {
		if is.Target != "" && is.Target != cloudgraph.InternetID && scn.Snapshot.Node(is.Target) == nil {
			r.Invented = append(r.Invented, is.Target)
		}
	}
	return r
}

// benchCodeAgent runs the AI Code Engineer over one TRULY-exploitable SQLi (string-concat
// query) and one SAFE decoy (parameterized query), both flagged by a scanner. The agent must
// open the source, CONFIRM the real one, and REFUSE the parameterized one — the grounding
// test a frontier model passes and a hallucinating one fails.
func benchCodeAgent(ctx context.Context, llm cloudengine.LLM) AgentResult {
	source := map[string]string{
		"api/handler.go": "package api\nimport \"net/http\"\nfunc Search(r *http.Request) {\n\tq := r.URL.Query().Get(\"q\")\n\tdb.Query(\"SELECT * FROM users WHERE name = '\" + q + \"'\")\n}\n",
		"api/safe.go":    "package api\nimport \"net/http\"\nfunc Get(r *http.Request) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.Query(\"SELECT * FROM users WHERE id = ?\", id)\n}\n",
	}
	findings := []types.Finding{
		{ID: "f-sqli", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh, Endpoint: "api/handler.go:5", Title: "SQL injection", CWE: []string{"CWE-89"}},
		{ID: "f-safe", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh, Endpoint: "api/safe.go:5", Title: "SQL injection (parameterized)", CWE: []string{"CWE-89"}},
	}
	r := AgentResult{Agent: "AI Code Engineer (codeagent)", Planted: 1} // one truly-exploitable
	rep, err := codeagent.Investigate(ctx, llm, &codeagent.Context{Repo: "acme/api", Findings: findings, Source: codeagent.NewMapSource(source)},
		codeagent.Options{MaxIters: 24})
	if err != nil || rep == nil {
		r.Missed = append(r.Missed, "f-sqli")
		return r
	}
	r.Calls = rep.Calls
	confirmed := map[string]bool{}
	for _, is := range rep.Issues {
		if is.Exploitable {
			confirmed[is.FindingID] = true
		}
	}
	if confirmed["f-sqli"] {
		r.Confirmed++
	} else {
		r.Missed = append(r.Missed, "f-sqli (real string-concat SQLi not confirmed)")
	}
	if confirmed["f-safe"] {
		r.Invented = append(r.Invented, "f-safe (parameterized query wrongly confirmed exploitable)")
	}
	return r
}

// RunAgentCoverage runs the cloud + code AI engineers against their planted estates.
func RunAgentCoverage(ctx context.Context, llm cloudengine.LLM) []AgentResult {
	return RunAgentCoverageOnly(ctx, llm, "")
}

// RunAgentCoverageOnly runs a subset: "cloud", "code", or "" for both. Useful for a
// tractable single-agent run against the manual dev proxy.
func RunAgentCoverageOnly(ctx context.Context, llm cloudengine.LLM, only string) []AgentResult {
	switch only {
	case "cloud":
		return []AgentResult{benchCloudAgent(ctx, llm)}
	case "code":
		return []AgentResult{benchCodeAgent(ctx, llm)}
	default:
		return []AgentResult{benchCloudAgent(ctx, llm), benchCodeAgent(ctx, llm)}
	}
}

// RenderAgentCoverageMarkdown renders the agent-layer scoreboard.
func RenderAgentCoverageMarkdown(rs []AgentResult) string {
	var b strings.Builder
	b.WriteString("\n## AI agent layer (frontier LLM via proxy / local Ollama)\n\n")
	b.WriteString("_The open-ended cloud + code engineers over a planted estate — recall of the real issues + ")
	b.WriteString("grounding (§10: a fabricated path / a false-confirmed safe finding is an invented issue)._\n\n")
	b.WriteString("| Agent | Recall | Confirmed | Invented | Tool calls |\n|---|---|---|---|---|\n")
	for _, r := range rs {
		inv := "0 ✓"
		if len(r.Invented) > 0 {
			inv = fmt.Sprintf("%d ✗ %v", len(r.Invented), r.Invented)
		}
		fmt.Fprintf(&b, "| %s | %.0f%% | %d/%d | %s | %d |\n", r.Agent, r.Recall()*100, r.Confirmed, r.Planted, inv, r.Calls)
	}
	return b.String()
}
