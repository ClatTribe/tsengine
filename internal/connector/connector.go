// Package connector links a tenant's external systems (GitHub, AWS, GCP, Google
// Workspace, M365, Slack) to the platform over OAuth, discovers the assets under
// each, turns provider events into scan triggers, and (for gated write actions)
// applies approved remediations. It is the #1 platform capability and the #1 moat —
// the maintained integration treadmill (docs/autonomous-team.md §3.2).
//
// Connectors are read-mostly: Discover + Watch are read paths; Apply is the only
// write path and is always reached AFTER a HITL gate (tier ≥ GateTier), never directly.
package connector

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Trigger is a request to (re)scan an asset, produced by Watch from a provider event
// (a push, a deploy) or by the scheduler.
type Trigger struct {
	TenantID     string
	ConnectionID string
	AssetTarget  string // the repo/account/domain the event concerns (matched to an Asset)
	Kind         string // platform.TriggerPush | TriggerDeploy | TriggerSchedule | TriggerManual
}

// Connector is one external-system integration. Implementations must keep the OAuth
// token out of returned values (it lives in the secret store, referenced by
// Connection.SecretRef); the platform passes the resolved token via TokenFunc.
type Connector interface {
	Kind() string
	// OAuthURL returns the provider's consent URL for the given CSRF state.
	OAuthURL(state, redirectURI string) string
	// Exchange swaps an OAuth callback code for a Connection (token already stored;
	// the returned Connection carries only the SecretRef + account metadata).
	Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error)
	// Discover lists the assets reachable under a connection (repos, accounts, ...).
	Discover(ctx context.Context, c platform.Connection, token string) ([]platform.Asset, error)
	// Watch parses a provider webhook payload into zero or more triggers.
	Watch(ctx context.Context, c platform.Connection, event []byte) ([]Trigger, error)
	// Apply executes an approved remediation (the only write path; gated upstream).
	Apply(ctx context.Context, c platform.Connection, token string, a platform.Action) error
}

// Registry resolves connectors by kind.
type Registry struct{ byKind map[string]Connector }

// NewRegistry builds a registry from the given connectors.
func NewRegistry(cs ...Connector) *Registry {
	r := &Registry{byKind: map[string]Connector{}}
	for _, c := range cs {
		r.byKind[c.Kind()] = c
	}
	return r
}

// Get returns the connector for a kind, or an error if none is registered.
func (r *Registry) Get(kind string) (Connector, error) {
	c, ok := r.byKind[kind]
	if !ok {
		return nil, fmt.Errorf("connector: no connector registered for kind %q", kind)
	}
	return c, nil
}

// Kinds lists the registered connector kinds.
func (r *Registry) Kinds() []string {
	out := make([]string, 0, len(r.byKind))
	for k := range r.byKind {
		out = append(out, k)
	}
	return out
}
