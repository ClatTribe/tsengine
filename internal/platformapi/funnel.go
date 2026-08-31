package platformapi

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ClatTribe/tsengine/internal/funnel"
	"github.com/ClatTribe/tsengine/internal/obsv"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// publicAssessCount is the number of public /v1/assess assessments served since this process
// started. Incremented in handlePublicAssess after its validity + rate-limit gates.
//
// A COUNT AND NOTHING ELSE. The caller is an anonymous stranger checking their own domain;
// recording WHICH domain would build a list of who is evaluating their security posture,
// which is the sort of record this product exists to argue against keeping. That choice is
// why the free-scan → signup rate is reported as declined rather than computed — see
// internal/funnel's rule 3.
var publicAssessCount atomic.Int64

// PublicAssessCount exposes the counter for the metrics registration in cmd/platform.
func PublicAssessCount() float64 { return float64(publicAssessCount.Load()) }

// RegisterFunnelMetrics publishes the scan counter to Prometheus. Called once at startup; the
// scraper is what makes the series durable across restarts.
func RegisterFunnelMetrics() { obsv.RegisterPublicAssessCount(PublicAssessCount) }

// handleFunnel serves the activation funnel: free scan → signup → connect → first finding →
// agent enabled.
//
// OPERATOR-GATED, NOT TENANT-SCOPED. This aggregates across every tenant, so it sits behind
// the platform token exactly like the cross-tenant practitioner desk (§18.2 invariant 2
// holds: a tenant SESSION still cannot reach it, and it returns no tenant's findings — only
// counts and timestamps of their own account's progress).
//
//	GET /v1/funnel?days=30
//
// The window is a SIGNUP COHORT, not activity in the period. The report says so in its own
// body rather than relying on this comment, because the number travels and the comment does
// not.
func (d Deps) handleFunnel(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("store not configured"))
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()

	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			writeJSON(w, http.StatusBadRequest, errBody("days must be a whole number between 1 and 3650"))
			return
		}
		days = n
	}
	// To is exclusive and set to the start of tomorrow so today is fully included; From is
	// inclusive. Adjacent windows therefore tile without double-counting a tenant.
	to := now.Truncate(24*time.Hour).AddDate(0, 0, 1)
	from := to.AddDate(0, 0, -days)

	tenants, err := d.Store.ListTenants(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}

	journeys := make([]funnel.Journey, 0, len(tenants))
	for _, t := range tenants {
		j := funnel.Journey{TenantID: t.ID, SignedUpAt: t.CreatedAt, AgentEnabled: agentEnabled(t), AgentOwnKey: t.LLM != nil}
		// Only the cohort's journeys need their later stages resolved. Everything else is
		// filtered out by Compute anyway, and each one costs two store reads — on a platform
		// with thousands of tenants that is the difference between a page load and a timeout.
		if t.CreatedAt.Before(from) || !t.CreatedAt.Before(to) {
			journeys = append(journeys, j)
			continue
		}
		if conns, err := d.Store.ListConnections(ctx, t.ID); err == nil {
			var active []time.Time
			for _, c := range conns {
				// A revoked or degraded connection is not progress: the funnel asks whether
				// the product can see the customer's estate, and through a dead connection it
				// cannot.
				if c.Status == platform.ConnActive {
					active = append(active, c.CreatedAt)
				}
			}
			j.ConnectedAt = funnel.FirstActiveConnection(active)
		}
		if fs, err := d.Store.ListFindings(ctx, t.ID, store.FindingFilter{}); err == nil {
			for _, f := range fs {
				if f.DiscoveredAt.IsZero() {
					continue
				}
				if j.FirstFindingAt.IsZero() || f.DiscoveredAt.Before(j.FirstFindingAt) {
					j.FirstFindingAt = f.DiscoveredAt
				}
			}
		}
		journeys = append(journeys, j)
	}

	writeJSON(w, http.StatusOK, funnel.Compute(funnel.Input{
		From: from, To: to, Now: now, Journeys: journeys,
		FreeScans:     int(publicAssessCount.Load()),
		ScansMeasured: true,
		ScansBasis: "public GET /v1/assess, counted after its validity and rate-limit gates. " +
			"IN-PROCESS since this platform started, so it resets on restart — the durable " +
			"series is the Prometheus counter tsengine_public_assess_total on /metrics.",
	}))
}

// agentEnabled is the "agent enabled" stage: the customer took the action that switches the
// AI engineer on. Either they configured their own LLM (works on any plan), or their plan
// entitles the operator-funded one.
//
// It is CURRENT STATE — neither has a timestamp, which is the reason the whole report is a
// cohort rather than a series of events.
func agentEnabled(t platform.Tenant) bool {
	if t.LLM != nil {
		return true
	}
	return platform.Entitlements(t.Plan).AIEnabled
}
