package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Fetcher pulls a live operate.Workspace using an access token (satisfied by
// *operate.GWorkspace). It never holds credentials — the token is resolved per call.
type Fetcher interface {
	Fetch(ctx context.Context, token string, now time.Time) (operate.Workspace, error)
}

// DomainEnricher resolves the live email-auth posture (DMARC/SPF/DKIM) of a set of
// domains (satisfied by *operate.EmailAuth). Optional: when set, the live source fills in
// a workspace's email-auth posture from public DNS — the provider user-fetch only yields
// accounts, never the sending domains' DNS records.
type DomainEnricher interface {
	FetchDomains(ctx context.Context, domains []string) []operate.DomainConfig
}

// LiveWorkspaceSource is a WorkspaceSource that fetches the snapshot live from the
// asset's connected provider: it finds the asset's Connection, resolves the vaulted
// token, and calls the Fetcher registered for the connection's kind (gworkspace, m365,
// …). This is the production path behind the WorkspaceSource seam (SnapshotSource is the
// file-based MVP).
type LiveWorkspaceSource struct {
	Store     store.Store
	Tokens    Tokens
	Fetchers  map[string]Fetcher // by connection kind (platform.ConnGWorkspace / ConnM365 / …)
	EmailAuth DomainEnricher     // optional: live DMARC/SPF/DKIM enrichment via DNS
}

// Workspace resolves the asset's connection token and fetches the live workspace via
// the fetcher for that provider.
func (l *LiveWorkspaceSource) Workspace(ctx context.Context, a platform.Asset) (operate.Workspace, error) {
	conns, err := l.Store.ListConnections(ctx, a.TenantID)
	if err != nil {
		return operate.Workspace{}, err
	}
	for _, c := range conns {
		if c.ID != a.ConnectionID {
			continue
		}
		f := l.Fetchers[c.Kind]
		if f == nil {
			return operate.Workspace{}, fmt.Errorf("operate: no live fetcher for provider %q", c.Kind)
		}
		tok, terr := l.Tokens.Resolve(ctx, c)
		if terr != nil {
			return operate.Workspace{}, fmt.Errorf("operate: resolve token: %w", terr)
		}
		ws, ferr := f.Fetch(ctx, tok, time.Time{})
		if ferr != nil {
			return ws, ferr
		}
		// Enrich email-auth posture live: the provider fetch yields users, not the
		// sending domains' DNS. Derive the domains from the users and resolve DMARC/SPF/
		// DKIM. Only when an enricher is wired and the fetch didn't already supply domains.
		if l.EmailAuth != nil && len(ws.Domains) == 0 {
			if domains := operate.DomainsFromUsers(ws.Users); len(domains) > 0 {
				ws.Domains = l.EmailAuth.FetchDomains(ctx, domains)
			}
		}
		return ws, nil
	}
	return operate.Workspace{}, fmt.Errorf("operate: no connection %s for workspace asset %s", a.ConnectionID, a.Target)
}

// CompositeSource prefers a snapshot file (asset Meta[SnapshotKey]) when present, else
// falls back to the live source — so an operator can run on an exported snapshot OR a
// live connection with no config change.
type CompositeSource struct {
	Snapshot WorkspaceSource
	Live     WorkspaceSource
}

// Workspace routes to the snapshot source when the asset names one, else the live source.
func (c CompositeSource) Workspace(ctx context.Context, a platform.Asset) (operate.Workspace, error) {
	if a.Meta[SnapshotKey] != "" && c.Snapshot != nil {
		return c.Snapshot.Workspace(ctx, a)
	}
	if c.Live != nil {
		return c.Live.Workspace(ctx, a)
	}
	return operate.Workspace{}, fmt.Errorf("operate: no workspace source for asset %s (no snapshot, no live connection)", a.Target)
}
