package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Client is the host-side HTTP client to the tool-server. One per scan;
// short-lived alongside Info.
type Client struct {
	info *Info
	http *http.Client
}

// NewClient constructs a Client for the given sandbox Info.
//
// The underlying http.Client has no hard timeout — call-time deadlines
// ride on the ctx passed to Execute. Long-running scans (nuclei with
// thousands of templates can take minutes) need this. Cancellation
// flows through the request context.
func NewClient(info *Info) *Client {
	return &Client{
		info: info,
		http: newHTTPClient(0),
	}
}

// ExecuteRequest is the wire payload for POST /execute.
type ExecuteRequest struct {
	Tool string    `json:"tool"`
	Args tool.Args `json:"args,omitempty"`
}

// Execute dispatches a tool inside the sandbox and returns its Result.
// The L1.5 hook chain runs on the host AFTER this returns — Execute is
// transport only.
func (c *Client) Execute(ctx context.Context, toolName string, args tool.Args) (tool.Result, error) {
	if toolName == "" {
		return tool.Result{}, errors.New("sandbox.Execute: empty tool name")
	}
	args = rewriteLoopbackArgs(args)
	body, err := json.Marshal(ExecuteRequest{Tool: toolName, Args: args})
	if err != nil {
		return tool.Result{}, fmt.Errorf("sandbox.Execute: marshal: %w", err)
	}
	req, err := requestWithCtx(ctx, http.MethodPost, c.info.APIURL+"/execute", bytes.NewReader(body))
	if err != nil {
		return tool.Result{}, fmt.Errorf("sandbox.Execute: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.info.AuthToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return tool.Result{}, fmt.Errorf("sandbox.Execute: do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tool.Result{}, fmt.Errorf("sandbox.Execute: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return tool.Result{}, fmt.Errorf("sandbox.Execute: tool-server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var out tool.Result
	if err := json.Unmarshal(respBody, &out); err != nil {
		return tool.Result{}, fmt.Errorf("sandbox.Execute: decode response: %w (body: %s)", err, string(respBody))
	}
	return out, nil
}

// CorpusInfo mirrors the tool-server's /corpus response — installed
// signature/template/DB versions, best-effort.
type CorpusInfo struct {
	NucleiTemplates string            `json:"nuclei_templates,omitempty"`
	NucleiEngine    string            `json:"nuclei_engine,omitempty"`
	TrivyDBUpdated  string            `json:"trivy_db_updated,omitempty"`
	ToolVersions    map[string]string `json:"tool_versions,omitempty"`
}

// Corpus queries the sandbox for installed corpus versions. Used to
// populate vulnerabilities.json's corpus block (CLAUDE.md §10).
func (c *Client) Corpus(ctx context.Context) (CorpusInfo, error) {
	req, err := requestWithCtx(ctx, http.MethodGet, c.info.APIURL+"/corpus", nil)
	if err != nil {
		return CorpusInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.info.AuthToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return CorpusInfo{}, fmt.Errorf("sandbox.Corpus: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return CorpusInfo{}, fmt.Errorf("sandbox.Corpus: status %d", resp.StatusCode)
	}
	var out CorpusInfo
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CorpusInfo{}, fmt.Errorf("sandbox.Corpus: decode: %w", err)
	}
	return out, nil
}

// Healthz is a thin probe used by Spawn and by health-check tooling.
func (c *Client) Healthz(ctx context.Context) error {
	req, err := requestWithCtx(ctx, http.MethodGet, c.info.APIURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sandbox.Healthz: status %d", resp.StatusCode)
	}
	return nil
}

// loopbackHostArgs are the arg keys that carry a URL or host the sandbox
// must dial. A loopback host in any of these refers to the HOST machine
// (where the target runs), not the sandbox container — so it's rewritten
// to host.docker.internal. Other args (payloads, field names) are left
// untouched: rewriting arbitrary string values could corrupt a payload.
var loopbackHostArgs = []string{"target", "targets", "login_url", "url", "urls"}

// loopbackHosts are the host tokens that, inside the sandbox, would point at
// the sandbox itself rather than the host running the target — so they are
// rewritten to host.docker.internal to reach the host. 0.0.0.0 is deliberately
// EXCLUDED: it is not a legitimate connect/scan target (use localhost or
// 127.0.0.1; the platform rejects 0.0.0.0 as a non-public asset anyway) and it
// is a classic SSRF-filter bypass token — leaving it un-rewritten keeps a
// 0.0.0.0 arg pointing at the (harmless) sandbox, never the host gateway, so it
// can't be used to punch through the sandbox's network isolation to a host-local
// service. (Scoping the whole rewrite to the scan target's host — so a loopback
// in any arg of a REMOTE-target scan is never host-rewritten — needs the scan
// target threaded into Execute; that's the documented follow-on, and the L2
// agent's args are already scope-gated in internal/l2/adapters/prober.go.)
var loopbackHosts = []string{"127.0.0.1", "localhost", "[::1]", "::1"}

const sandboxHostAlias = "host.docker.internal"

// rewriteLoopbackArgs returns a copy of args with loopback host tokens in
// the known URL/host keys rewritten to host.docker.internal. This is the
// host→sandbox boundary fix: a scan targeting http://localhost:8098 means
// "the app on the host", but inside the sandbox localhost is the sandbox.
// strix shipped network probes without this and watched ip_address recall
// collapse from 1.0 to 0.0 (CLAUDE.md §5.1 host/sandbox boundary).
//
// Conservative: only the loopbackHostArgs keys are touched, and only the
// host token is swapped (scheme/port/path preserved). Newline-joined
// lists (targets) are rewritten per line.
func rewriteLoopbackArgs(args tool.Args) tool.Args {
	if len(args) == 0 {
		return args
	}
	out := make(tool.Args, len(args))
	for k, v := range args {
		out[k] = v
	}
	for _, key := range loopbackHostArgs {
		s, ok := out[key].(string)
		if !ok || s == "" {
			continue
		}
		out[key] = rewriteLoopbackString(s)
	}
	return out
}

func rewriteLoopbackString(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = rewriteOneLoopback(ln)
	}
	return strings.Join(lines, "\n")
}

// rewriteOneLoopback swaps a leading-host loopback token for the sandbox
// alias. Handles bare hosts ("localhost:8098"), scheme URLs
// ("http://127.0.0.1/x"), and the host token alone.
func rewriteOneLoopback(s string) string {
	for _, lh := range loopbackHosts {
		// scheme://host... and //host...
		for _, sep := range []string{"://", "//"} {
			if i := strings.Index(s, sep+lh); i >= 0 {
				after := i + len(sep) + len(lh)
				// Only rewrite when the match ends at a host boundary
				// (port colon, path slash, or end) — avoids matching
				// "localhosting.example.com".
				if after == len(s) || s[after] == ':' || s[after] == '/' {
					return s[:i+len(sep)] + sandboxHostAlias + s[after:]
				}
			}
		}
		// bare "host:port" or exact "host"
		if s == lh {
			return sandboxHostAlias
		}
		if strings.HasPrefix(s, lh+":") {
			return sandboxHostAlias + s[len(lh):]
		}
	}
	return s
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func requestWithCtx(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, url, body)
}
