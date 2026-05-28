package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func requestWithCtx(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, url, body)
}
