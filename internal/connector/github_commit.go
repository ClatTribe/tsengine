package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// github_commit.go gives the GitHub connector the ability to actually COMMIT a fix — the missing link
// between "the AI Security Engineer wrote a patch" and "the customer sees a pull request with the code".
// Before this, Apply could only POST /pulls with a `head` branch that something else had to have created,
// so a fix PR could never carry a diff (competitor parity gap: Aikido/Snyk ship fix PRs).
//
// It uses the Git Data API so a multi-file fix lands as ONE atomic commit on a NEW branch:
//
//	base ref → base commit/tree → blob per file → tree → commit → new branch ref
//
// The PR itself is still opened by Apply (unchanged), and the whole path is still HITL-gated (§18.2
// inv. 3) — a PR is a proposal a human reviews and merges, never a direct write to the default branch.
// Requires the GitHub App `contents: write` scope; without it GitHub answers 403 and we surface it
// honestly (never a silent "fixed").

// CommitFiles creates `branch` off `base` containing `files` (path→new content) as one commit, and
// returns nothing but an error — the caller opens the PR from `branch`. Empty files → error (there is
// nothing honest to commit).
func (g *GitHub) CommitFiles(ctx context.Context, token, full, base, branch, message string, files map[string]string) error {
	if len(files) == 0 {
		return fmt.Errorf("github: refusing to commit an empty patch")
	}
	if base == "" {
		base = "main"
	}
	// 1. base ref → the commit we branch from
	baseSHA, err := g.refSHA(ctx, token, full, base)
	if err != nil {
		return err
	}
	// 2. that commit's tree
	baseTree, err := g.commitTree(ctx, token, full, baseSHA)
	if err != nil {
		return err
	}
	// 3. a blob per changed file
	type treeEnt struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	ents := make([]treeEnt, 0, len(files))
	for _, path := range sortedKeys(files) { // deterministic order → reproducible tree
		blobSHA, err := g.createBlob(ctx, token, full, files[path])
		if err != nil {
			return err
		}
		ents = append(ents, treeEnt{Path: path, Mode: "100644", Type: "blob", SHA: blobSHA})
	}
	// 4. a tree on top of the base tree (base_tree → untouched files are inherited)
	var treeResp struct {
		SHA string `json:"sha"`
	}
	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/trees",
		map[string]any{"base_tree": baseTree, "tree": ents}, &treeResp); err != nil {
		return err
	}
	// 5. the commit
	var commitResp struct {
		SHA string `json:"sha"`
	}
	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/commits",
		map[string]any{"message": message, "tree": treeResp.SHA, "parents": []string{baseSHA}}, &commitResp); err != nil {
		return err
	}
	// 6. the new branch ref (a NEW branch — never a force-push over an existing one)
	return g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/refs",
		map[string]any{"ref": "refs/heads/" + branch, "sha": commitResp.SHA}, nil)
}

func (g *GitHub) refSHA(ctx context.Context, token, full, base string) (string, error) {
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.ghJSON(ctx, token, http.MethodGet, "/repos/"+full+"/git/ref/heads/"+base, nil, &out); err != nil {
		return "", err
	}
	if out.Object.SHA == "" {
		return "", fmt.Errorf("github: base branch %q not found", base)
	}
	return out.Object.SHA, nil
}

func (g *GitHub) commitTree(ctx context.Context, token, full, sha string) (string, error) {
	var out struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := g.ghJSON(ctx, token, http.MethodGet, "/repos/"+full+"/git/commits/"+sha, nil, &out); err != nil {
		return "", err
	}
	if out.Tree.SHA == "" {
		return "", fmt.Errorf("github: commit %s has no tree", sha)
	}
	return out.Tree.SHA, nil
}

func (g *GitHub) createBlob(ctx context.Context, token, full, content string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	if err := g.ghJSON(ctx, token, http.MethodPost, "/repos/"+full+"/git/blobs",
		map[string]any{"content": content, "encoding": "utf-8"}, &out); err != nil {
		return "", err
	}
	if out.SHA == "" {
		return "", fmt.Errorf("github: blob create returned no sha")
	}
	return out.SHA, nil
}

// ghJSON is the shared GitHub JSON call: body may be nil (GET); out may be nil (response ignored).
// A non-2xx is an error carrying the status (a 403 = the App lacks `contents: write` — surfaced, not swallowed).
func (g *GitHub) ghJSON(ctx context.Context, token, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
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
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github: %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// FetchFile reads ONE file's content at `ref` (a branch/sha; empty = the repo default). This is the
// other half of an honest AI fix: the engineer must reason over the REAL source, not a finding's
// metadata. Returns the decoded text. A directory, a binary blob, or a too-large file is an error —
// never a silently-empty "source" the model would then hallucinate a patch against.
func (g *GitHub) FetchFile(ctx context.Context, token, full, ref, path string) (string, error) {
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Type     string `json:"type"`
		Size     int    `json:"size"`
	}
	url := "/repos/" + full + "/contents/" + path
	if ref != "" {
		url += "?ref=" + ref
	}
	if err := g.ghJSON(ctx, token, http.MethodGet, url, nil, &out); err != nil {
		return "", err
	}
	if out.Type != "" && out.Type != "file" {
		return "", fmt.Errorf("github: %s is a %s, not a file", path, out.Type)
	}
	if out.Encoding != "base64" {
		// GitHub omits content for very large files and asks you to use the blob API.
		return "", fmt.Errorf("github: %s has no inline content (encoding %q, size %d) — too large to patch inline", path, out.Encoding, out.Size)
	}
	// the API wraps base64 at 60 cols
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return "", fmt.Errorf("github: decode %s: %w", path, err)
	}
	return string(dec), nil
}

// filesFrom extracts the fix payload (path→new file content) from an Action. Survives the JSON
// round-trip through the store (map[string]any). Non-string values are skipped — never guessed at.
func filesFrom(payload map[string]any) map[string]string {
	raw, ok := payload["files"]
	if !ok {
		return nil
	}
	switch m := raw.(type) {
	case map[string]string:
		return m
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
		return out
	}
	return nil
}

// safeBranchSuffix makes an action id safe for a git ref (alnum/-/_ only, bounded).
func safeBranchSuffix(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		}
		if b.Len() >= 40 {
			break
		}
	}
	if b.Len() == 0 {
		return "patch"
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// tiny insertion sort — avoids pulling sort into this file's import set for a handful of paths
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}
