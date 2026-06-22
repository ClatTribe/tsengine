package sspm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchGitHubOrg builds a GitHubOrg posture snapshot LIVE from the GitHub API, reusing the
// already-onboarded GitHub connection's token — so the SSPM checks run with no extra credential
// and no posted snapshot. It reads what the onboarding `read:org` scope covers: the org-level
// security config (org-wide 2FA enforcement, default repo permission, public-repo creation) plus,
// best-effort, the org's GHAS secret-scanning default and org webhooks.
//
// HONEST SCOPE: per-member 2FA status, the installed-app inventory, and outside-collaborator
// enumeration need broader scopes (admin:org) and heavy pagination, so those checks fire fully only
// via the posted-snapshot path (POST /v1/saas/github_org/snapshot). A field GitHub won't return
// with the granted scope stays its zero value — a securely-config'd org still yields zero findings
// (grounded, §10): we never invent a posture we couldn't read.
func FetchGitHubOrg(ctx context.Context, apiBase, org, token string, hc *http.Client) (GitHubOrg, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	apiBase = strings.TrimRight(apiBase, "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	if strings.TrimSpace(org) == "" {
		return GitHubOrg{}, fmt.Errorf("github org sync: empty org login")
	}

	var raw struct {
		Login                              string `json:"login"`
		TwoFactorRequirementEnabled        bool   `json:"two_factor_requirement_enabled"`
		DefaultRepositoryPermission        string `json:"default_repository_permission"`
		MembersCanCreatePublicRepositories bool   `json:"members_can_create_public_repositories"`
		SecurityAndAnalysis                struct {
			SecretScanning               struct{ Status string } `json:"secret_scanning"`
			SecretScanningPushProtection struct{ Status string } `json:"secret_scanning_push_protection"`
		} `json:"security_and_analysis"`
	}
	if err := ghGet(ctx, hc, apiBase+"/orgs/"+url.PathEscape(org), token, &raw); err != nil {
		return GitHubOrg{}, fmt.Errorf("github org sync: read org %q: %w", org, err)
	}

	snap := GitHubOrg{
		Login:                       raw.Login,
		TwoFactorRequired:           raw.TwoFactorRequirementEnabled,
		DefaultRepoPermission:       raw.DefaultRepositoryPermission,
		MembersCanCreatePublicRepos: raw.MembersCanCreatePublicRepositories,
		// secret scanning is "enabled" by default only when BOTH detection + push-protection are on.
		SecretScanningEnabled: strings.EqualFold(raw.SecurityAndAnalysis.SecretScanning.Status, "enabled") &&
			strings.EqualFold(raw.SecurityAndAnalysis.SecretScanningPushProtection.Status, "enabled"),
	}
	if snap.Login == "" {
		snap.Login = org
	}

	// Org webhooks — best-effort (needs admin:org_hook). A failure (insufficient scope) leaves
	// Webhooks empty so that check simply doesn't fire; it never fails the sync.
	var hooks []struct {
		Active bool `json:"active"`
		Config struct {
			URL         string `json:"url"`
			InsecureSSL string `json:"insecure_ssl"` // "0" = verify TLS, "1" = skip
		} `json:"config"`
	}
	if err := ghGet(ctx, hc, apiBase+"/orgs/"+url.PathEscape(org)+"/hooks", token, &hooks); err == nil {
		for _, h := range hooks {
			snap.Webhooks = append(snap.Webhooks, OrgWebhook{
				URL: h.Config.URL, Active: h.Active, SSLVerify: h.Config.InsecureSSL == "0",
			})
		}
	}
	return snap, nil
}

// ghGet performs an authenticated GitHub API GET and decodes the JSON body. A non-2xx is an error
// carrying the status so an insufficient-scope (403) surfaces honestly.
func ghGet(ctx context.Context, hc *http.Client, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}
