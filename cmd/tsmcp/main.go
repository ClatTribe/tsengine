// Command tsmcp exposes the AI Security Engineer's knowledge to a CODING AGENT over MCP.
//
// WHY THIS EXISTS. The product is reachable from a browser and a sales conversation. The moment a
// developer is actually fixing a vulnerability, they are in Claude Code or Cursor — and there we are not
// reachable at all. They alt-tab to a dashboard, or more likely they do not, and fix it from memory
// while the engine that knows the answer sits in another window. A competitor shipping an MCP server is
// inside that loop; we were not.
//
// READ-ONLY, AND THAT IS THE CORRECT SHAPE, NOT A LIMITATION. In an MCP session the coding agent is the
// actor: it writes the fix, it opens the PR, it runs the tests. What it lacks is knowledge of the estate
// — is this finding real, where does the vulnerability actually live, what should be fixed first. So
// this serves questions and never takes an action.
//
// The alternative would be a write tool (propose_fix, open_ticket) callable from a chat. That is a
// genuinely bad idea here and worth stating: a code-fix action is tier 1 in remediate's policy, which
// AUTO-APPLIES — it commits a branch and opens a real pull request. Exposing that over MCP would let a
// conversational agent write to a customer's repository with no desk, no approval and no ledger entry
// in between. The HITL gates live in the platform; a side door that bypasses them is not a feature.
//
// ONE tool POSTs — verify_fix — and it is still read-only in the sense that matters: it takes no
// action on the customer's systems. It returns a verdict (is this proposed patch sound?) over content
// the agent supplied; it opens no PR, files no ticket, and attacks nothing. The POST carries a body,
// not a mutation. The read-only line above is about side effects, not HTTP verbs.
//
// Transport is stdio JSON-RPC 2.0 — the MCP default — implemented directly. It is a read loop and
// encoding/json; a dependency for that would be more code to audit than the thing it replaces.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const protocolVersion = "2024-11-05"

func main() {
	base := strings.TrimRight(os.Getenv("TSENGINE_URL"), "/")
	token := os.Getenv("TSENGINE_TOKEN")
	if base == "" || token == "" {
		// stderr, not stdout: stdout is the JSON-RPC channel and anything else on it corrupts the stream.
		fmt.Fprintln(os.Stderr, "tsmcp: set TSENGINE_URL (e.g. https://app.example.com) and TSENGINE_TOKEN "+
			"(a session token from your workspace). Both are required — without them every tool would "+
			"answer 'unauthorized', which is a worse failure than refusing to start.")
		os.Exit(2)
	}
	srv := &server{base: base, token: token, http: &http.Client{Timeout: 30 * time.Second}}
	if err := srv.serve(os.Stdin, os.Stdout); err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "tsmcp:", err)
		os.Exit(1)
	}
}

type server struct {
	base  string
	token string
	http  *http.Client
}

// ---- JSON-RPC plumbing ----

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification => no reply
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *server) serve(in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(bufio.NewReader(in))
	enc := json.NewEncoder(out)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			return err // EOF is the normal shutdown
		}
		// A notification (no id) gets no reply — replying to one is a protocol violation that some
		// clients treat as a fatal stream error.
		if len(req.ID) == 0 {
			continue
		}
		res := response{JSONRPC: "2.0", ID: req.ID}
		result, err := s.dispatch(req)
		if err != nil {
			res.Error = &rpcError{Code: -32603, Message: err.Error()}
		} else {
			res.Result = result
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
}

func (s *server) dispatch(req request) (any, error) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "tsengine", "version": "0.1.0"},
		}, nil
	case "tools/list":
		return map[string]any{"tools": toolSchemas()}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, fmt.Errorf("bad tools/call params: %w", err)
		}
		text, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			// Surfaced as tool CONTENT with isError, not a transport error: the agent should see what
			// went wrong and can retry or ask differently, rather than the session dying.
			return map[string]any{
				"content": []any{map[string]any{"type": "text", "text": err.Error()}},
				"isError": true,
			}, nil
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}, nil
	default:
		return nil, fmt.Errorf("unsupported method %q", req.Method)
	}
}

// ---- the tools ----

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

// toolSchemas is the catalogue the coding agent sees. Deliberately SMALL — the same reasoning as the
// ≤12-tool cap in the L2 catalogue: past a handful of tools a model's selection accuracy degrades, and
// this list competes for attention with every other MCP server the developer has installed.
func toolSchemas() []map[string]any {
	return []map[string]any{
		{
			"name": "ask_security_estate",
			"description": "Ask about THIS codebase's real security estate in plain language — 'are we exposed " +
				"to log4j?', 'what critical findings are unproven?'. Answers from findings the security " +
				"engine actually recorded, with no model in the loop, so it cannot invent an exposure. An " +
				"empty answer means nothing matched, not that the question was bad.",
			"inputSchema": obj(map[string]any{"question": str("what to look for, in plain language")}, "question"),
		},
		{
			"name": "where_is_the_vulnerability",
			"description": "Given a finding id, rank the files in the connected repository that carry the sink " +
				"for that weakness — the answer to 'which file do I actually open?' when a scanner's " +
				"file:line is approximate or points at a lockfile. Grounded in the repo's real contents.",
			"inputSchema": obj(map[string]any{"finding_id": str("the finding id, e.g. f-123")}, "finding_id"),
		},
		{
			"name": "what_should_i_fix_first",
			"description": "The cross-surface attack paths and, more usefully, the CHOKE POINTS — the one " +
				"identifier or weakness that appears in the most paths, so a single fix collapses several. " +
				"Use this before picking what to work on; a ranked list of issues is not the same as knowing " +
				"which one has leverage.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name": "list_open_issues",
			"description": "The deduplicated open security issues for this workspace, worst first, each with " +
				"how confident the engine is (exploit-proven, corroborated by two tools, or a single-tool " +
				"pattern match to confirm before acting).",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name": "verify_fix",
			"description": "Before you open a PR, check whether a fix you wrote for a KNOWN finding is SOUND: " +
				"it actually changes the file, it changes the line the finding cites (not some other line), and " +
				"it still parses. Pass the finding id and your proposed NEW file content. This takes no action — " +
				"it opens no PR and attacks nothing, it just returns a verdict. It proves the patch is SOUND, " +
				"NOT that the vulnerability is closed: closure is only confirmed after the fix is deployed and the " +
				"scan + exploit are re-run. A clean result is not permission to skip review.",
			"inputSchema": obj(map[string]any{
				"finding_id": str("the finding this fix addresses, e.g. f-123"),
				"patched":    str("your proposed NEW content for the cited file (whole file)"),
				"original":   str("optional: the current content of the file, if the engine cannot read it from a connected repo"),
			}, "finding_id", "patched"),
		},
	}
}

func (s *server) callTool(name string, args map[string]any) (string, error) {
	arg := func(k string) string {
		v, _ := args[k].(string)
		return strings.TrimSpace(v)
	}
	switch name {
	case "ask_security_estate":
		q := arg("question")
		if q == "" {
			return "", fmt.Errorf("ask_security_estate needs a question")
		}
		var out struct {
			Answer string `json:"answer"`
		}
		if err := s.get("/v1/ask?q="+url.QueryEscape(q), &out); err != nil {
			return "", err
		}
		if strings.TrimSpace(out.Answer) == "" {
			return "Nothing in this workspace's findings matches that.", nil
		}
		return out.Answer, nil

	case "where_is_the_vulnerability":
		id := arg("finding_id")
		if id == "" {
			return "", fmt.Errorf("where_is_the_vulnerability needs a finding_id")
		}
		var out struct {
			Answer string `json:"answer"`
		}
		if err := s.get("/v1/findings/"+url.PathEscape(id)+"/localize", &out); err != nil {
			return "", err
		}
		return out.Answer, nil

	case "what_should_i_fix_first":
		var out struct {
			Count       int `json:"count"`
			ChokePoints []struct {
				Label string `json:"label"`
				Paths int    `json:"paths"`
				Why   string `json:"why"`
			} `json:"choke_points"`
		}
		if err := s.get("/v1/attack-paths", &out); err != nil {
			return "", err
		}
		if len(out.ChokePoints) == 0 {
			return fmt.Sprintf("%d attack path(s), and no shared choke point — these are separate pieces "+
				"of work rather than one fix with leverage.", out.Count), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d attack path(s). Highest leverage first:\n", out.Count)
		for i, c := range out.ChokePoints {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "%d. %s — in %d paths. %s\n", i+1, c.Label, c.Paths, c.Why)
		}
		return b.String(), nil

	case "list_open_issues":
		var out struct {
			Count  int `json:"count"`
			Issues []struct {
				Title        string `json:"title"`
				Severity     string `json:"severity"`
				Endpoint     string `json:"endpoint"`
				Confirmed    bool   `json:"confirmed"`
				Verification string `json:"verification_status"`
			} `json:"issues"`
		}
		if err := s.get("/v1/issues", &out); err != nil {
			return "", err
		}
		if len(out.Issues) == 0 {
			return "No open issues recorded. Note this reflects what has been SCANNED — it is not a " +
				"statement that nothing else exists.", nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d open issue(s):\n", out.Count)
		for i, is := range out.Issues {
			if i >= 20 {
				fmt.Fprintf(&b, "… and %d more\n", len(out.Issues)-20)
				break
			}
			conf := is.Verification
			if conf == "" {
				conf = "unconfirmed"
			}
			fmt.Fprintf(&b, "- [%s] %s (%s) — %s\n", is.Severity, is.Title, conf, is.Endpoint)
		}
		return b.String(), nil

	case "verify_fix":
		id, patched := arg("finding_id"), arg("patched")
		if id == "" || patched == "" {
			return "", fmt.Errorf("verify_fix needs a finding_id and the proposed patched file content")
		}
		reqBody := map[string]string{"patched": patched}
		if o := arg("original"); o != "" {
			reqBody["original"] = o
		}
		var out struct {
			Path      string `json:"path"`
			Soundness struct {
				Blocking bool   `json:"blocking"`
				Note     string `json:"note"`
				Checks   []struct {
					Name    string `json:"name"`
					Status  string `json:"status"`
					Message string `json:"message"`
				} `json:"checks"`
			} `json:"soundness"`
		}
		if err := s.post("/v1/findings/"+url.PathEscape(id)+"/verify-fix", reqBody, &out); err != nil {
			return "", err
		}
		var b strings.Builder
		if out.Soundness.Blocking {
			fmt.Fprintf(&b, "DO NOT OPEN THIS PR YET — the fix for %s (%s) failed a soundness check:\n", id, out.Path)
		} else {
			fmt.Fprintf(&b, "The fix for %s (%s) is sound:\n", id, out.Path)
		}
		for _, c := range out.Soundness.Checks {
			fmt.Fprintf(&b, "- [%s] %s\n", c.Status, c.Message)
		}
		b.WriteString(out.Soundness.Note)
		return b.String(), nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// get calls the platform API with the workspace token.
func (s *server) get(path string, into any) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the security engine at %s: %w", s.base, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("the security engine rejected this token (%d) — check TSENGINE_TOKEN", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("security engine returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, into)
}

// post calls the platform API with a JSON body. It is used ONLY by verify_fix, which takes no action
// on the customer's systems — it returns a verdict over content the agent supplied. The POST carries a
// body; it does not mutate anything. This server never exposes a tool that writes (opens a PR, files a
// ticket, suppresses a finding): those bypass the HITL desk and belong in the platform, never a chat.
func (s *server) post(path string, body any, into any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.base+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the security engine at %s: %w", s.base, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("the security engine rejected this token (%d) — check TSENGINE_TOKEN", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("security engine returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return json.Unmarshal(respBody, into)
}
