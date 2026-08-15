package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// cloudsync.go: read the customer's live AWS state instead of waiting for someone to post it.
//
// POST /v1/cloud/sync assumes the read-only role recorded at connect time, reads what it can, and
// runs the result through applyCloudInventory — the SAME path a posted inventory takes, so drift
// detection, the timeline and the snapshot behave identically. Two paths that both "ingest an
// inventory" would drift apart, and the customer could not tell which one produced what they are
// looking at.
//
// # It reports coverage, and that is not decoration
//
// The fetcher reads object storage, IAM and EC2 — but any surface can fail independently (a role
// missing one permission reads the others fine). cloudgraph builds attack paths out of principals and
// network reach, so an inventory missing them cannot form a path — an agent reasoning over it finds
// none and could call an account clean when its identity layer was never examined. The response
// therefore leads with awsfetch.Result.Coverage(), which names what was read, what was not, and what
// that costs.
//
// A sync that cannot say what it covered would be a worse product than no sync at all, because the
// result LOOKS live.

// AWSFetcherFor builds a live fetcher for one connection. Injectable so the endpoint is testable
// without AWS credentials; nil → the endpoint reports that live fetch is not available on this
// deployment rather than returning an empty account.
type AWSFetcherFor func(conn platform.Connection) awsfetch.Fetcher

// ErrCloudSyncUnavailable is re-exported from runner, which owns the scheduled-sync contract. It
// means this deployment or tenant cannot do a live read right now — no snapshot store, no fetcher
// wired, or no connected AWS account — as distinct from a read that FAILED. The scheduled caller
// stays silent for the former and logs the latter, because "not configured" every fifteen minutes is
// noise while "the role stopped working" is the signal.
var ErrCloudSyncUnavailable = runner.ErrCloudSyncUnavailable

// SyncCloudInventory reads the tenant's live AWS account and applies it, returning the drift findings
// and a summary.
//
// Exported because the scheduled monitoring pass needs it. Everything below the HTTP layer was already
// here — the fetcher, the drift diff, the timeline — but the only thing that ever called it was a
// human clicking Sync. That made cloud the one connected surface whose change detection was manual:
// SaaS posture and OSINT both re-sync every pass, so a newly-public GitHub repo or a newly-exposed
// host opens an incident on its own, while a bucket that went public at 2am waited for someone to
// press a button.
//
// Returns the stored drift findings so the caller can fold them into the pass's present state — see
// applyCloudInventory on why handing them back is load-bearing rather than convenience.
func (d Deps) SyncCloudInventory(ctx context.Context, tenantID string) ([]types.Finding, awsfetch.Result, error) {
	if d.CloudSnapshots == nil || d.AWSFetcher == nil {
		return nil, awsfetch.Result{}, ErrCloudSyncUnavailable
	}
	conn, err := d.awsConnection(ctx, tenantID)
	if err != nil {
		// No connected account is not a failure — most tenants have not connected AWS.
		return nil, awsfetch.Result{}, fmt.Errorf("%w: %s", ErrCloudSyncUnavailable, err)
	}
	res, ferr := d.AWSFetcher(conn).Fetch(ctx)
	if ferr != nil {
		return nil, res, ferr
	}
	inv := awsinventory.Build(res.Raw)
	invJSON, merr := json.Marshal(inv)
	if merr != nil {
		return nil, res, merr
	}
	drift, _, aerr := d.applyCloudInventory(ctx, tenantID, inv, invJSON,
		"live AWS read via the connected read-only role → stored for the AI cloud engineer")
	if aerr != nil {
		return nil, res, aerr
	}
	return drift, res, nil
}

// handleCloudSync fetches live AWS state for the tenant's connected account on demand.
func (d Deps) handleCloudSync(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.CloudSnapshots == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("cloud snapshot store not configured"))
		return
	}
	if d.AWSFetcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "live cloud read is not enabled on this deployment — the AI cloud engineer runs " +
				"on the inventory you post to /v1/cloud/inventory until it is",
			"reason": "live_fetch_unavailable",
		})
		return
	}

	conn, err := d.awsConnection(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  err.Error(),
			"reason": "no_aws_connection",
		})
		return
	}

	res, ferr := d.AWSFetcher(conn).Fetch(r.Context())
	if ferr != nil {
		// A failed read is reported as a failure. Returning a summary of an empty inventory here would
		// be indistinguishable from an account with nothing in it.
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":    "could not read the AWS account: " + ferr.Error(),
			"reason":   "fetch_failed",
			"coverage": res.Coverage(),
		})
		return
	}

	inv := awsinventory.Build(res.Raw)
	invJSON, merr := json.Marshal(inv)
	if merr != nil {
		respond(w, nil, merr)
		return
	}
	_, summary, aerr := d.applyCloudInventory(r.Context(), tenantID, inv, invJSON,
		"live AWS read via the connected read-only role → stored for the AI cloud engineer")
	if aerr != nil {
		respond(w, nil, aerr)
		return
	}

	// Coverage rides on every response, including the successful one — especially the successful one.
	summary["coverage"] = res.Coverage()
	summary["sources_read"] = res.Sources
	summary["not_read"] = res.Skipped
	writeJSON(w, http.StatusOK, summary)
}

// awsConnection finds the tenant's active AWS connection. The role ARN recorded at connect time IS
// the credential (see connector.AWS.Exchange), so a connection without one cannot be read from.
func (d Deps) awsConnection(ctx context.Context, tenantID string) (platform.Connection, error) {
	conns, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return platform.Connection{}, err
	}
	for _, c := range conns {
		if c.Kind != platform.ConnAWS {
			continue
		}
		if strings.TrimSpace(c.SecretRef) == "" {
			return platform.Connection{}, fmt.Errorf("the AWS connection has no role recorded — reconnect it")
		}
		if c.Status != platform.ConnActive {
			return platform.Connection{}, fmt.Errorf("the AWS connection is %s, not active", c.Status)
		}
		return c, nil
	}
	return platform.Connection{}, fmt.Errorf("no AWS account is connected — connect one first")
}
