package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// fixpr.go is the AI Security Engineer's REAL fix: finding → the actual source → a patch → a gated
// pull request that carries a diff. It is the on-demand half of competitor parity (Aikido/Snyk ship
// "high-confidence fix PRs"); the existing /autofix endpoint stays as the cheap advice view, which
// reasons from the finding's metadata alone and cannot produce an applicable patch.
//
// Deliberately USER-TRIGGERED: a fix costs the customer's own model budget (§18.5 bring-your-own-key),
// so we spend it when they ask, never automatically on a scan.
//
// Grounded (§10) at every step: the model sees the REAL file (never a guess); it can only rewrite files
// we supplied (codeagent drops anything else); and the result is a PROPOSED, HITL-gated action — the
// PR is a proposal a human reviews, never a write to the default branch (§18.2 inv. 3).

// sourceFetcher is the connector capability this path needs (satisfied by *connector.GitHub). Kept as
// a local interface so a provider without it degrades honestly instead of panicking.
type sourceFetcher interface {
	FetchFile(ctx context.Context, token, full, ref, path string) (string, error)
}

type fixPRReq struct {
	// AssetID names the repository to patch. A code finding's endpoint is a file:line — it does NOT
	// carry the repo — so when a tenant has more than one repository we ASK rather than guess which
	// codebase to open a PR against.
	AssetID string `json:"asset_id"`
}

func (d Deps) handleFixPR(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	llm := d.resolveAgentLLM(r.Context(), tenantID)
	if llm == nil {
		writeJSON(w, http.StatusBadRequest, errBody("an AI fix needs a model: configure one in Settings → LLM (your own key — any Anthropic/OpenAI-compatible provider, or a local model)"))
		return
	}
	var req fixPRReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // optional body
	}

	f, err := d.findingByID(r.Context(), tenantID, id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if f == nil {
		writeJSON(w, http.StatusNotFound, errBody("no finding with id "+id))
		return
	}
	path := sourcePathOf(*f)
	if path == "" {
		writeJSON(w, http.StatusBadRequest, errBody("this finding has no source location to patch (its endpoint is not a file:line) — use /autofix for guidance instead"))
		return
	}

	asset, aerr := d.repoAssetFor(r.Context(), tenantID, req.AssetID)
	if aerr != "" {
		writeJSON(w, http.StatusBadRequest, errBody(aerr))
		return
	}
	full := asset.Meta["full_name"]
	if full == "" {
		full = asset.Target
	}

	// the connector + the tenant's vaulted token for this connection
	conn, cerr := d.connectionByID(r.Context(), tenantID, asset.ConnectionID)
	if cerr != "" {
		writeJSON(w, http.StatusBadRequest, errBody(cerr))
		return
	}
	c, err := d.Connectors.Get(conn.Kind)
	if err != nil {
		respond(w, nil, err)
		return
	}
	sf, ok := c.(sourceFetcher)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("fix PRs aren't supported for "+conn.Kind+" yet — it can't read source"))
		return
	}
	if d.Runner == nil || d.Runner.Tokens == nil {
		writeJSON(w, http.StatusBadRequest, errBody("no token resolver configured — cannot read the repository"))
		return
	}
	token, terr := d.Runner.Tokens.Resolve(r.Context(), conn)
	if terr != nil {
		respond(w, nil, terr)
		return
	}

	// READ THE REAL SOURCE — the engineer never patches code it hasn't seen.
	src, ferr := sf.FetchFile(r.Context(), token, full, "", path)
	if ferr != nil {
		respond(w, nil, ferr)
		return
	}

	patch, perr := codeagent.ProposePatch(r.Context(), llm, codeagent.Finding{
		Class:    fixClassOf(*f),
		Endpoint: f.Endpoint,
		Detail:   strings.TrimSpace(f.Title + "\n" + f.Description),
	}, []codeagent.SourceFile{{Path: path, Content: src}})
	if perr != nil {
		respond(w, nil, perr)
		return
	}
	if patch.Empty() {
		// The engineer declining to patch is an HONEST outcome, not an error — never fabricate a fix.
		writeJSON(w, http.StatusOK, map[string]any{
			"finding_id": id, "patched": false,
			"reason": "the engineer did not produce a safe patch for this finding — review it manually or use /autofix for guidance",
		})
		return
	}

	files := make(map[string]string, len(patch.Files))
	for _, pf := range patch.Files {
		files[pf.Path] = pf.Content
	}
	act, ok := remediate.ProposeWithPatch(*f, asset, files, nil)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("no remediation action applies to this finding"))
		return
	}
	// HITL gate: the action is PROPOSED and goes to the desk — approving it is what opens the PR.
	if d.Submitter != nil {
		act, err = d.Submitter.Submit(r.Context(), act)
		if err != nil {
			respond(w, nil, err)
			return
		}
	} else if err := d.Store.PutAction(r.Context(), act); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("fix PR proposed", "l2-fix-pr",
			map[string]any{"tenant_id": tenantID, "finding_id": id, "action_id": act.ID, "files": len(files)},
			"AI Security Engineer patched real source")
	}
	changed := make([]string, 0, len(files))
	for p := range files {
		changed = append(changed, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"finding_id": id, "patched": true, "action_id": act.ID, "status": act.Status,
		"files_changed": changed, "repo": full,
	})
}

// findingByID looks one finding up in the tenant's set.
func (d Deps) findingByID(ctx context.Context, tenantID, id string) (*types.Finding, error) {
	fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i], nil
		}
	}
	return nil, nil
}

// repoAssetFor resolves WHICH repository to patch. A code finding's endpoint is a file:line and does
// not name the repo, so: an explicit asset_id wins; else a single repository asset is unambiguous;
// else we refuse and ask (never guess which codebase to open a PR against).
func (d Deps) repoAssetFor(ctx context.Context, tenantID, assetID string) (platform.Asset, string) {
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return platform.Asset{}, "could not list assets: " + err.Error()
	}
	var repos []platform.Asset
	for _, a := range assets {
		if a.Type == "repository" {
			repos = append(repos, a)
		}
	}
	if assetID != "" {
		for _, a := range repos {
			if a.ID == assetID {
				return a, ""
			}
		}
		return platform.Asset{}, "no repository asset with id " + assetID
	}
	switch len(repos) {
	case 0:
		return platform.Asset{}, "no repository connected — connect a repo before asking for a fix PR"
	case 1:
		return repos[0], ""
	default:
		return platform.Asset{}, "more than one repository is connected — pass asset_id to say which one to patch"
	}
}

// connectionByID finds the asset's connection.
func (d Deps) connectionByID(ctx context.Context, tenantID, id string) (platform.Connection, string) {
	if id == "" {
		return platform.Connection{}, "this asset has no connection — reconnect the repository"
	}
	cs, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return platform.Connection{}, "could not list connections: " + err.Error()
	}
	for _, c := range cs {
		if c.ID == id {
			return c, ""
		}
	}
	return platform.Connection{}, "the asset's connection is missing — reconnect the repository"
}

// sourcePathOf extracts the file path from a code finding's endpoint ("app/login.php:42" →
// "app/login.php"). Returns "" for anything that isn't a source location (a URL, an ARN, a host) —
// those have no file to patch.
func sourcePathOf(f types.Finding) string {
	e := strings.TrimSpace(f.Endpoint)
	if e == "" || strings.Contains(e, "://") {
		return ""
	}
	if i := strings.LastIndex(e, ":"); i > 0 {
		if rest := e[i+1:]; rest != "" && strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			e = e[:i] // strip a trailing :line
		}
	}
	if e == "" || strings.HasPrefix(e, "/") || strings.Contains(e, "..") || !strings.Contains(e, ".") {
		return "" // absolute/traversal/extension-less → not a repo-relative source file
	}
	return e
}

// fixClassOf gives the engineer a class hint from what the finding actually says (CWE first, else the
// rule id) — grounded, never invented.
func fixClassOf(f types.Finding) string {
	if len(f.CWE) > 0 && f.CWE[0] != "" {
		return f.CWE[0]
	}
	if f.RuleID != "" {
		return f.RuleID
	}
	return "vulnerability"
}
