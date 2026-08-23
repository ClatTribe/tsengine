package platformapi

import (
	"context"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// cloudprober.go is the half of ADR 0024 P1a that turns the provider dry-run from a tested adapter
// into a capability: constructing it for a tenant, from the connection they already made.
//
// P1a shipped cloudprobe.AWSSimulator with its decision mapping and its refusals, and stated plainly
// that live wiring was the remaining half. Leaving it there would have been C11 again in a fresh
// package — a correct, tested primitive that nothing constructs, so no customer ever benefits and the
// documents slowly start describing it as though they do.
//
// THE ROLE IS THE ONE ALREADY THERE. iam:SimulatePrincipalPolicy is a READ, so it belongs inside the
// scoped read-only cross-account role recorded at connect time — the same one awsfetch uses, with the
// tenant id as the external-id guard (confused-deputy protection). No new credential, no new consent
// screen, nothing for an operator to configure per tenant.
//
// Nil is a first-class answer. Most tenants have no connected account, and a deployment may have no
// live AWS path at all; in both cases the agent's check_reachable says the provider was not asked
// rather than reporting a path unproven or proven (§10). ProbeCoverage() returns nil in that case too,
// so a run with zero probes renders as "we did not look" instead of a clean tally.

// proberOrNil builds the tenant's provider dry-run, or nil when this deployment has no live path.
//
// CloudProber is injected rather than constructed here so package platformapi stays SDK-free — the
// same isolation the *remediate packages and awsfetch use.
func (d Deps) proberOrNil(ctx context.Context, tenantID string) cloudagent.ExploitProber {
	if d.CloudProber == nil {
		return nil
	}
	conn, err := d.awsConnection(ctx, tenantID)
	if err != nil {
		return nil // no connected account — most tenants
	}
	return d.CloudProber(conn)
}

// ProbeStamp is the RFC3339 clock the prober stamps answers with. Exported so cmd/platform builds one
// consistent with proof freshness (ADR 0024 P1c parses this exact layout; a differently-formatted
// stamp would make every proof's age unreadable and therefore StandingUnknown).
func ProbeStamp() string { return time.Now().UTC().Format(time.RFC3339) }

// CloudProberFunc is the injected constructor's shape.
type CloudProberFunc func(platform.Connection) cloudagent.ExploitProber
