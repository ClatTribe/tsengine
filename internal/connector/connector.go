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
	"net/http"

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

// WebhookVerifier authenticates an inbound provider webhook against the shared webhook
// secret, before any re-scan is triggered (defends the endpoint against spoofed events).
// Optional capability — a connector that doesn't implement it skips verification.
type WebhookVerifier interface {
	VerifyWebhook(h http.Header, body []byte, secret string) error
}

// WebhookRegistrar registers a push webhook on a discovered target (e.g. a repo) so future
// provider events trigger instant re-scans — continuous monitoring becomes event-driven,
// not just scheduled. Optional capability; called best-effort at connect time with the
// shared secret (the same one WebhookVerifier checks). Idempotent: a target that already
// has the hook is a no-op success.
type WebhookRegistrar interface {
	RegisterWebhook(ctx context.Context, token, target, callbackURL, secret string) error
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

// Configurable is implemented by connectors whose usability depends on deploy-time credentials
// (an OAuth client id/secret pair). It exists because an unconfigured connector failed SILENTLY
// AND LATE: OAuthURL would happily build ".../authorize?client_id=&redirect_uri=..." and the
// customer landed on a provider error page, with nothing logged server-side to explain it.
//
// This is an OPTIONAL interface — a connector that does not implement it is treated as
// configured. That is correct for AWS/GCP/Azure, which onboard via a console/CloudFormation
// link and need no client secret at all.
type Configurable interface {
	// Configured reports whether this connector has the credentials it needs to start an
	// OAuth flow in this deployment.
	Configured() bool
}

// ConfigHinter names the settings a connector needs, for the operator who has to supply them.
//
// Without this the not-configured error said "set its CLIENT_ID and CLIENT_SECRET" for EVERY kind.
// That is right for the OAuth connectors and wrong for the three cloud ones, which are role-assumption
// flows with no client secret at all — so an operator connecting AWS, the product's headline surface,
// was sent looking for a variable that does not exist for it.
type ConfigHinter interface {
	// ConfigHint returns the env var names this deployment must set, most specific first.
	ConfigHint() string
}

// ConfigHint returns operator-facing guidance for an unconfigured connector, falling back to the
// OAuth pair that most connectors do use.
func ConfigHint(c Connector) string {
	if ch, ok := c.(ConfigHinter); ok {
		if h := ch.ConfigHint(); h != "" {
			return h
		}
	}
	return "its CLIENT_ID and CLIENT_SECRET"
}

// IsConfigured reports whether c is usable in this deployment.
func IsConfigured(c Connector) bool {
	if cc, ok := c.(Configurable); ok {
		return cc.Configured()
	}
	return true
}

// ConfiguredKinds lists only the kinds this deployment can actually complete an onboarding flow
// for — what the UI should offer. Kinds() still returns everything registered.
func (r *Registry) ConfiguredKinds() []string {
	out := make([]string, 0, len(r.byKind))
	for k, c := range r.byKind {
		if IsConfigured(c) {
			out = append(out, k)
		}
	}
	return out
}
