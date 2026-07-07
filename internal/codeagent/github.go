package codeagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// GitHubSource is the LIVE SourceProvider: it reads the connected repository's source over the GitHub API,
// so the code-depth agent can open real code without a local checkout. It implements the same interface as
// MapSource — the agent + grounding are unchanged; this just swaps the oracle from an in-memory map to the
// live repo. The token is the credential-gated half (reuse the onboarded GitHub connection's token); the
// query-builder + response parsing are pure. Fetched files are cached so a re-read (and Grep over already-read
// files) costs no extra API call.
//
// ReadFile is line-accurate (Contents API → the whole file → slice). Grep uses GitHub's code-search API,
// which is FILE-level (no line numbers), so a hit reports line 0 — the agent then read_sources the file to
// pinpoint it. Honest: if the token lacks search access, Grep degrades to the cached files only.
type GitHubSource struct {
	Owner, Repo, Ref string // ref = branch or sha (empty → the repo default branch)
	Token            string
	HTTP             *http.Client
	Base             string // API base (default https://api.github.com; overridable for tests)

	cache map[string]string
}

// NewGitHubSource builds a live source for owner/repo at ref (branch/sha; empty = default branch).
func NewGitHubSource(owner, repo, ref, token string) *GitHubSource {
	return &GitHubSource{
		Owner: owner, Repo: repo, Ref: ref, Token: token,
		HTTP:  &http.Client{Timeout: 20 * time.Second},
		Base:  "https://api.github.com",
		cache: map[string]string{},
	}
}

func (g *GitHubSource) base() string {
	if g.Base != "" {
		return g.Base
	}
	return "https://api.github.com"
}

// fetch returns the full file content (cached), via the Contents API.
func (g *GitHubSource) fetch(ctx context.Context, path string) (string, error) {
	if g.cache == nil {
		g.cache = map[string]string{}
	}
	if c, ok := g.cache[path]; ok {
		return c, nil
	}
	u := fmt.Sprintf("%s/repos/%s/%s/contents/%s", g.base(), g.Owner, g.Repo, path)
	if g.Ref != "" {
		u += "?ref=" + url.QueryEscape(g.Ref)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github contents %s: HTTP %d", path, resp.StatusCode)
	}
	var body struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if derr := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body); derr != nil {
		return "", derr
	}
	content := body.Content
	if body.Encoding == "base64" {
		dec, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
		if derr != nil {
			return "", derr
		}
		content = string(dec)
	}
	g.cache[path] = content
	return content, nil
}

func (g *GitHubSource) ReadFile(ctx context.Context, path string, startLine, endLine int) (string, error) {
	content, err := g.fetch(ctx, path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(content, "\n")
	if startLine < 1 {
		startLine = 1
	}
	if endLine <= 0 || endLine > len(lines) {
		endLine = len(lines)
	}
	if startLine > len(lines) {
		return "", nil
	}
	var b strings.Builder
	for i := startLine; i <= endLine; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// Grep first scans already-fetched files (line-accurate, free), then falls back to the GitHub code-search
// API for files not yet read (file-level → line 0). A search failure (missing scope / rate limit) is not
// fatal — the cached-file matches still return.
func (g *GitHubSource) Grep(ctx context.Context, pattern string, maxHits int) ([]GrepHit, error) {
	var hits []GrepHit
	// 1) cached files — line-accurate.
	paths := make([]string, 0, len(g.cache))
	for p := range g.cache {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		for i, ln := range strings.Split(g.cache[p], "\n") {
			if strings.Contains(ln, pattern) {
				hits = append(hits, GrepHit{Path: p, Line: i + 1, Text: ln})
				if len(hits) >= maxHits {
					return hits, nil
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, h := range hits {
		seen[h.Path] = true
	}
	// 2) code search for files we haven't read (file-level; line 0). Best-effort.
	found, _ := g.searchFiles(ctx, pattern, maxHits)
	for _, p := range found {
		if seen[p] {
			continue
		}
		hits = append(hits, GrepHit{Path: p, Line: 0, Text: "(matched by code search — read_source to pinpoint)"})
		if len(hits) >= maxHits {
			break
		}
	}
	return hits, nil
}

func (g *GitHubSource) searchFiles(ctx context.Context, pattern string, maxHits int) ([]string, error) {
	q := fmt.Sprintf("%s repo:%s/%s", pattern, g.Owner, g.Repo)
	u := fmt.Sprintf("%s/search/code?q=%s&per_page=%d", g.base(), url.QueryEscape(q), maxHits)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github search: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Items []struct {
			Path string `json:"path"`
		} `json:"items"`
	}
	if derr := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); derr != nil {
		return nil, derr
	}
	out := make([]string, 0, len(body.Items))
	for _, it := range body.Items {
		out = append(out, it.Path)
	}
	return out, nil
}

// Files returns the paths fetched so far (the live provider has no cheap full-tree listing; the agent
// discovers paths via the findings' endpoints + grep_code).
func (g *GitHubSource) Files() []string {
	out := make([]string, 0, len(g.cache))
	for p := range g.cache {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
