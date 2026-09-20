package platformapi

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/prbot"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// GitHubInstallationKey is the Connection.Config key holding the GitHub App installation id for
// the tenant's GitHub connection — a plain identifier (like Account), never a credential.
const GitHubInstallationKey = "github_app_installation_id"

// prPosterFor resolves the live poster for a tenant, or nil with the REASON it cannot post. The
// reason is rendered to the customer and returned on the pr-check, because "the bot did not
// comment" has three different fixes — the operator configures the App, the customer installs it
// and records the installation id, the customer connects GitHub — and a bare "not posted" sends
// them to the wrong one.
func (d Deps) prPosterFor(ctx context.Context, tenantID string) (prbot.Poster, string) {
	if d.GitHubApp == nil {
		return nil, "no GitHub App is configured on this deployment (GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY)"
	}
	conn, ok := d.githubConnection(ctx, tenantID)
	if !ok {
		return nil, "no GitHub connection on this workspace"
	}
	inst := conn.Config[GitHubInstallationKey]
	if inst == "" {
		return nil, "the GitHub App is not installed on this workspace's organisation — install it and record the installation id in Settings → Pull-request review"
	}
	return &prbot.GitHubPoster{
		APIBase: d.GitHubAPIBase,
		Token:   func(ctx context.Context) (string, error) { return d.GitHubApp.InstallationToken(ctx, inst) },
	}, ""
}

// githubConnection returns the tenant's first GitHub connection.
func (d Deps) githubConnection(ctx context.Context, tenantID string) (platform.Connection, bool) {
	conns, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return platform.Connection{}, false
	}
	for _, c := range conns {
		if c.Kind == platform.ConnGitHub {
			return c, true
		}
	}
	return platform.Connection{}, false
}
