package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/connector/gcpfetch"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// gcpsync.go: read a connected Google Cloud project LIVE, the way cloudsync.go reads AWS.
//
// Before this, a GCP project was the one cloud whose attack paths depended entirely on somebody posting
// an export. Connecting a project recorded the project id and stopped: gcpiam, gcpwif and the Rhino
// privesc catalogue (23/23) had nothing to evaluate unless a customer built a collector. The fetcher is
// internal/connector/gcpfetch; this file is the door, and it is deliberately the SAME door the posted
// GCP inventory uses — gcpinventory.Build, connector.CoverGCP, the gcpwif CI-identity assessment and
// applyCloudInventoryWithCoverage — so a project read live and one posted by hand cannot disagree. That
// shape has been found broken four times in this tree (the two-doors-disagree bug); a fifth door built
// on a parallel path would be the fifth.

// GCPFetcher reads one project. *gcpfetch.Fetcher satisfies it.
type GCPFetcher interface {
	Fetch(ctx context.Context) (gcpfetch.Result, error)
}

// GCPFetcherFor builds a live fetcher for one GCP connection. Nil → live GCP read is not available on
// this deployment, reported as such rather than as an empty project.
type GCPFetcherFor func(conn platform.Connection) GCPFetcher

// gcpConnections returns the tenant's active GCP connections. Every one is read: snapshots are keyed
// per account, so two projects are two baselines rather than one overwriting the other.
func (d Deps) gcpConnections(ctx context.Context, tenantID string) ([]platform.Connection, error) {
	conns, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []platform.Connection
	for _, c := range conns {
		if c.Kind == platform.ConnGCP && c.Status == platform.ConnActive && strings.TrimSpace(c.Account) != "" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no GCP project is connected — connect one first")
	}
	return out, nil
}

// GCPSyncResult is one project's read.
type GCPSyncResult struct {
	Project string
	Fetch   gcpfetch.Result
	Summary map[string]any
	Err     error
}

// SyncGCPInventory reads every connected project and applies each, returning the drift findings.
//
// A project that fails to read is reported in its result and in the error; the others still apply. The
// error is returned whenever ANY project failed, so the scheduled pass does not claim the cloud as
// covered while one project went unread (a covered source lets the reconciler resolve its incidents).
func (d Deps) SyncGCPInventory(ctx context.Context, tenantID string) ([]types.Finding, []GCPSyncResult, error) {
	if d.CloudSnapshots == nil || d.GCPFetcher == nil {
		return nil, nil, ErrCloudSyncUnavailable
	}
	conns, err := d.gcpConnections(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrCloudSyncUnavailable, err)
	}
	var drift []types.Finding
	var results []GCPSyncResult
	var errs []error
	for _, c := range conns {
		f, r := d.syncGCPProject(ctx, tenantID, c)
		drift = append(drift, f...)
		results = append(results, r)
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("GCP project %s: %w", r.Project, r.Err))
		}
	}
	return drift, results, errors.Join(errs...)
}

func (d Deps) syncGCPProject(ctx context.Context, tenantID string, c platform.Connection) ([]types.Finding, GCPSyncResult) {
	out := GCPSyncResult{Project: c.Account}
	res, ferr := d.GCPFetcher(c).Fetch(ctx)
	out.Fetch = res
	if ferr != nil {
		out.Err = ferr
		return nil, out
	}
	if res.Raw.ProjectID == "" {
		res.Raw.ProjectID = c.Account
	}
	inv := gcpinventory.Build(res.Raw)
	// The posted door refuses an empty inventory because it cannot be told apart from a collector that
	// failed, and storing it would make every real resource look newly created on the next sync. The
	// live door holds the same line.
	if len(inv.Resources) == 0 {
		out.Err = errors.New("the project read returned no resources, so it was not stored — an empty " +
			"project cannot be told apart from a read that saw nothing")
		return nil, out
	}
	invJSON, err := json.Marshal(inv)
	if err != nil {
		out.Err = err
		return nil, out
	}
	rawJSON, err := json.Marshal(res.Raw)
	if err != nil {
		out.Err = err
		return nil, out
	}
	ciFindings, ciNotAssessed := ciIdentityAssess("gcp", rawJSON)
	d.persistCIIdentityFindings(ctx, tenantID, ciFindings)

	coverage := connector.CoverGCP(res.Raw)
	// WHAT THE READ COULD NOT SEE is stored beside what the snapshot could not answer. A role whose
	// definition went unread, a page of service accounts cut short: each is a reason an empty attack-path
	// page might be a blind spot rather than a clean project, and the person reading that page is not the
	// scheduler that ran the read.
	extra := map[string]string{}
	for k, v := range ciNotAssessed {
		extra[k] = v
	}
	for surface, why := range res.Skipped {
		extra["not-read: "+surface] = why
	}
	if len(extra) > 0 {
		if coverage.Notes == nil {
			coverage.Notes = map[string]string{}
		}
		for k, v := range extra {
			coverage.Notes[k] = v
		}
	}
	drift, summary, aerr := d.applyCloudInventoryWithCoverage(ctx, tenantID, inv, invJSON,
		"live GCP read via the read-only access granted to tsengine's service account → stored for the AI cloud engineer",
		coverage, nil)
	if aerr != nil {
		out.Err = aerr
		return nil, out
	}
	summary["coverage"] = coverage.Summary()
	if !coverage.Complete() {
		summary["coverage_gaps"] = coverage.Notes
	}
	summary["sources_read"] = res.Sources
	summary["not_read"] = res.Skipped
	out.Summary = summary
	return drift, out
}

// SyncClouds is the scheduled pass's single entry point: every connected cloud, each through its own
// door. A cloud that is simply not connected is not an error; one whose read FAILED is, and its drift
// from the clouds that did read still comes back so the pass can fold it into present state (a drift
// finding stored but not handed back is opened and then immediately resolved by the same pass).
func (d Deps) SyncClouds(ctx context.Context, tenantID string) ([]types.Finding, error) {
	var drift []types.Finding
	var errs []error
	ran := 0
	awsDrift, _, aerr := d.SyncCloudInventory(ctx, tenantID)
	drift = append(drift, awsDrift...)
	switch {
	case aerr == nil:
		ran++
	case !errors.Is(aerr, ErrCloudSyncUnavailable):
		errs = append(errs, fmt.Errorf("AWS: %w", aerr))
	}
	gcpDrift, _, gerr := d.SyncGCPInventory(ctx, tenantID)
	drift = append(drift, gcpDrift...)
	switch {
	case gerr == nil:
		ran++
	case !errors.Is(gerr, ErrCloudSyncUnavailable):
		errs = append(errs, gerr)
	}
	if len(errs) > 0 {
		return drift, errors.Join(errs...)
	}
	if ran == 0 {
		return nil, ErrCloudSyncUnavailable
	}
	return drift, nil
}

// handleGCPSync reads the tenant's connected GCP project(s) on demand (POST /v1/cloud/sync?provider=gcp).
func (d Deps) handleGCPSync(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.CloudSnapshots == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("cloud snapshot store not configured"))
		return
	}
	if d.GCPFetcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "live GCP read is not enabled on this deployment — the AI cloud engineer runs on the " +
				"inventory you post to /v1/cloud/inventory?provider=gcp until it is",
			"reason": "live_fetch_unavailable",
		})
		return
	}
	if _, err := d.gcpConnections(r.Context(), tenantID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "reason": "no_gcp_connection"})
		return
	}
	_, results, _ := d.SyncGCPInventory(r.Context(), tenantID)
	sort.Slice(results, func(i, j int) bool { return results[i].Project < results[j].Project })
	projects := make([]map[string]any, 0, len(results))
	failed := 0
	for _, res := range results {
		p := map[string]any{"project": res.Project}
		if res.Err != nil {
			failed++
			// A failed read is reported as a failure, with whatever it did manage to say about coverage.
			// A summary of an empty project here would be indistinguishable from a project with nothing in it.
			p["error"] = "could not read the GCP project: " + res.Err.Error()
			p["reason"] = "fetch_failed"
			p["sources_read"] = res.Fetch.Sources
			p["not_read"] = res.Fetch.Skipped
		} else {
			for k, v := range res.Summary {
				p[k] = v
			}
		}
		projects = append(projects, p)
	}
	status := http.StatusOK
	if failed == len(results) {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{"projects": projects, "failed": failed})
}
