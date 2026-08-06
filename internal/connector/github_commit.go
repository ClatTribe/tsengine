package connector

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
)

// github_commit.go gives the GitHub connector the ability to actually COMMIT a fix — the missing link
// between "the AI Security Engineer wrote a patch" and "the customer sees a pull request with the code".
//
// Before this, Apply could only POST /pulls with a `head` branch that SOMETHING ELSE had to have
// created — and nothing did. So a fix PR could never carry a diff: the autofix agent produced patched
// file contents that had no way to reach the repository. That is the competitor-parity gap (Aikido and
// Snyk both ship fix PRs), and it is why "AI fix" stopped at a suggestion box.
//
// The Git Data API is used so a multi-file fix lands as ONE atomic commit on a NEW branch:
//
//	ref(base) → commit → tree → blob(s) → tree → commit → ref(new branch)
//
// Atomicity matters for a security fix: a partial commit could leave a repo in a state where the
// vulnerability is half-patched and the app is broken, which is worse than not fixing it.
//
// The PR itself is still opened by Apply, and the whole path is still HITL-gated (§18.2 inv. 3) — a
// pull request is a PROPOSAL a human reviews and merges, never a direct write to the default branch.
// Requires the GitHub App's `contents: write` scope; without it GitHub answers 403 and we surface that
// honestly rather than reporting a fix that never landed.

// fileMode is the git mode for a normal non-executable file.
const fileMode = "100644"

// CommitFiles creates `branch` off `base` containing `files` (path → new content) as a single commit.
// The caller opens the PR from `branch`.
//
// An empty file set is an error: there is nothing honest to commit, and creating an empty branch
// would produce a PR with no diff — exactly the misleading artifact this function exists to prevent.
func (g *GitHub) CommitFiles(ctx context.Context, token, full, base, branch, message string, files map[string]string) error {
	if full == "" || branch == "" {
		return fmt.Errorf("github: commit needs a repo and a branch")
	}
	if len(files) == 0 {
		return fmt.Errorf("github: refusing to commit an empty patch to %s (nothing to change)", full)
	}
	if base == "" {
		base = "main"
	}
	if message == "" {
		message = "tsengine: security fix"
	}

	baseSHA, err := g.refSHA(ctx, token, full, base)
	if err != nil {
		return err
	}
	baseTree, err := g.commitTree(ctx, token, full, baseSHA)
	if err != nil {
		return err
	}

	// Deterministic path order so the same patch produces the same tree — a fix that reorders
	// randomly is needlessly hard to review or reproduce (§10).
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(paths))
	for _, p := range paths {
		blob, berr := g.createBlob(ctx, token, full, files[p])
		if berr != nil {
			return berr
		}
		entries = append(entries, treeEntry{Path: p, Mode: fileMode, Type: "blob", SHA: blob})
	}

	var tree struct {
		SHA string `json:"sha"`
	}
	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/trees", map[string]any{
		"base_tree": baseTree, "tree": entries,
	}, &tree); err != nil {
		return fmt.Errorf("github: create tree: %w", err)
	}

	var commit struct {
		SHA string `json:"sha"`
	}
	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/commits", map[string]any{
		"message": message, "tree": tree.SHA, "parents": []string{baseSHA},
	}, &commit); err != nil {
		return fmt.Errorf("github: create commit: %w", err)
	}

	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/refs", map[string]any{
		"ref": "refs/heads/" + branch, "sha": commit.SHA,
	}, nil); err != nil {
		return fmt.Errorf("github: create branch %q: %w", branch, err)
	}
	return nil
}

// FetchFile reads ONE file's content at `ref` (a branch or sha; empty = the repo default branch).
//
// This is the read half the fix loop needs: the code engineer must see the CURRENT source to patch it
// correctly. Without it the agent was reasoning from finding metadata alone — a file:line and a rule
// id — which is how you get a patch that does not apply.
func (g *GitHub) FetchFile(ctx context.Context, token, full, path, ref string) (string, error) {
	if full == "" || path == "" {
		return "", fmt.Errorf("github: fetch needs a repo and a path")
	}
	p := "/repos/" + full + "/contents/" + strings.TrimPrefix(path, "/")
	if ref != "" {
		p += "?ref=" + url.QueryEscape(ref)
	}
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := g.ghJSON(ctx, token, http.MethodGet, p, nil, &out); err != nil {
		return "", fmt.Errorf("github: fetch %s: %w", path, err)
	}
	if out.Encoding != "base64" {
		// Refuse rather than return something that only looks like source — a wrong "current content"
		// silently produces a patch against the wrong file.
		return "", fmt.Errorf("github: %s returned unsupported encoding %q", path, out.Encoding)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return "", fmt.Errorf("github: decode %s: %w", path, err)
	}
	return string(raw), nil
}

// refSHA resolves a branch name to its head commit sha.
func (g *GitHub) refSHA(ctx context.Context, token, full, base string) (string, error) {
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.ghJSON(ctx, token, http.MethodGet, "/repos/"+full+"/git/ref/heads/"+base, nil, &out); err != nil {
		return "", fmt.Errorf("github: resolve base branch %q: %w", base, err)
	}
	if out.Object.SHA == "" {
		return "", fmt.Errorf("github: base branch %q has no head commit", base)
	}
	return out.Object.SHA, nil
}

// commitTree returns the tree sha of a commit (the base tree the new tree extends).
func (g *GitHub) commitTree(ctx context.Context, token, full, sha string) (string, error) {
	var out struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := g.ghJSON(ctx, token, http.MethodGet, "/repos/"+full+"/git/commits/"+sha, nil, &out); err != nil {
		return "", fmt.Errorf("github: read base commit: %w", err)
	}
	return out.Tree.SHA, nil
}

// createBlob uploads one file's content and returns its blob sha.
func (g *GitHub) createBlob(ctx context.Context, token, full, content string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	// base64 so arbitrary bytes (and any encoding) survive the round trip intact.
	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/blobs", map[string]any{
		"content": base64.StdEncoding.EncodeToString([]byte(content)), "encoding": "base64",
	}, &out); err != nil {
		return "", fmt.Errorf("github: create blob: %w", err)
	}
	return out.SHA, nil
}

// ghJSON is the shared GitHub JSON call: body may be nil (GET); out may be nil (response ignored).
//
// A non-2xx becomes an error carrying the status AND the response body. That matters here: a 403 is
// almost always "the App lacks `contents: write`", and an operator needs to see that rather than a
// bare failure — the alternative is a fix that silently never lands.
func (g *GitHub) ghJSON(ctx context.Context, token, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.APIBase, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(payload))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("HTTP 403 — the GitHub App likely lacks the `contents: write` scope: %s", msg)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// filesFrom extracts a path→content patch from an action payload, tolerating both the typed
// map[string]string a Go caller builds and the map[string]any a JSON round-trip produces.
//
// A non-string value is SKIPPED rather than coerced: committing a stringified number as file content
// would corrupt the file, and a corrupted "fix" is worse than no fix.
func filesFrom(payload map[string]any) map[string]string {
	if payload == nil {
		return nil
	}
	switch v := payload["files"].(type) {
	case map[string]string:
		return v
	case map[string]any:
		out := make(map[string]string, len(v))
		for path, content := range v {
			if s, ok := content.(string); ok {
				out[path] = s
			}
		}
		return out
	}
	return nil
}
