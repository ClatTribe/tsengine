package remediate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// JiraResolver returns a tenant's OWN Jira destination (base/email/project + the opened API token,
// resolved from the sealed ref by the caller, which holds the store + Vault). ok=false → the tenant
// has none configured, so the operator fallback files the ticket. Best-effort: a resolver error is
// a silent false.
type JiraResolver func(ctx context.Context, tenantID string) (baseURL, email, token, project string, ok bool)

// TenantFiler routes a file_ticket action to the action's OWN tenant's Jira (the per-tenant
// destination the customer set via UX), falling back to the operator-global filer. This makes
// ticketing multi-tenant: tenant A's tickets land in tenant A's Jira, not the operator's project.
// Implements remediate.Filer.
type TenantFiler struct {
	Resolve  JiraResolver
	Fallback Filer        // operator-global Jira (may be nil → a no-destination ticket is a recorded no-op)
	HTTP     *http.Client // optional override for the per-tenant Jira client (tests); nil → connector.NewJira's SSRF-guarded default
}

// FileTicket files into the tenant's own Jira when configured, else the operator fallback.
func (t TenantFiler) FileTicket(ctx context.Context, a platform.Action) error {
	if t.Resolve != nil {
		if base, email, token, project, ok := t.Resolve(ctx, a.TenantID); ok {
			j := connector.NewJira(base, email, token, project)
			if t.HTTP != nil {
				j.HTTP = t.HTTP
			}
			return j.FileTicket(ctx, a)
		}
	}
	if t.Fallback != nil {
		return t.Fallback.FileTicket(ctx, a)
	}
	return nil
}

// FileTicketRef files like FileTicket and returns the created ticket, stamped with WHOSE tracker holds
// it — the read-back must use the same credentials that filed it.
func (t TenantFiler) FileTicketRef(ctx context.Context, a platform.Action) (platform.TicketRef, error) {
	if t.Resolve != nil {
		if base, email, token, project, ok := t.Resolve(ctx, a.TenantID); ok {
			j := connector.NewJira(base, email, token, project)
			if t.HTTP != nil {
				j.HTTP = t.HTTP
			}
			ref, err := j.FileTicketRef(ctx, a)
			ref.Destination = "tenant"
			return ref, err
		}
	}
	if t.Fallback == nil {
		return platform.TicketRef{}, nil
	}
	if rf, ok := t.Fallback.(RefFiler); ok {
		ref, err := rf.FileTicketRef(ctx, a)
		ref.Destination = "operator"
		return ref, err
	}
	return platform.TicketRef{}, t.Fallback.FileTicket(ctx, a)
}

// TicketTracker reads a delivered ticket back and writes to it (satisfied by *connector.Jira).
type TicketTracker interface {
	TicketStatus(ctx context.Context, key string) (connector.IssueStatus, error)
	AddComment(ctx context.Context, key, text string) error
}

// ErrDestinationMoved is returned when the tenant's Jira now points somewhere other than the site that
// holds the ticket. Reading the same key from a different site would read a DIFFERENT issue and report
// its status as this one's — a stranger's "Done" closing our loop.
var ErrDestinationMoved = errors.New("the Jira destination changed after this ticket was filed, so it can no longer be read back")

// TrackerFor returns the tracker that holds ref, using the same credentials that filed it.
func (t TenantFiler) TrackerFor(ctx context.Context, tenantID string, ref platform.TicketRef) (TicketTracker, error) {
	if ref.System != "jira" {
		return nil, fmt.Errorf("no read-back for %q tickets", ref.System)
	}
	switch ref.Destination {
	case "tenant":
		if t.Resolve == nil {
			return nil, errors.New("no tenant Jira resolver")
		}
		base, email, token, project, ok := t.Resolve(ctx, tenantID)
		if !ok {
			return nil, errors.New("the workspace's Jira is no longer configured")
		}
		if ref.URL != "" && !strings.HasPrefix(ref.URL, strings.TrimRight(base, "/")+"/") {
			return nil, ErrDestinationMoved
		}
		j := connector.NewJira(base, email, token, project)
		if t.HTTP != nil {
			j.HTTP = t.HTTP
		}
		return j, nil
	case "operator":
		if tr, ok := t.Fallback.(TicketTracker); ok {
			return tr, nil
		}
		return nil, errors.New("the operator tracker cannot be read back")
	}
	return nil, fmt.Errorf("unknown ticket destination %q", ref.Destination)
}
