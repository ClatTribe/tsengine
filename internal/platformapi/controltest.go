package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/controltest"
)

// handleIngestControlDetections turns a WAF's own logs into the sensor stream detection-validation
// reads (ADR 0027 — the control plane). It answers "did the perimeter control our customer ALREADY
// runs — Cloudflare or AWS WAF — notice our attack, and did it BLOCK it?" without asking them to
// deploy a RASP agent our ICP does not have.
//
// POST /v1/control-plane/detections?source=aws_waf|cloudflare
// Body: a single WAF record or an array of them (the shape GetSampledRequests / the Cloudflare
// firewall-events feed returns). The tenant's own active probe canaries are collected from stored
// engagements and matched against each request line, so a matching log carries the STRONG marker tie
// back to the exact probe that caused it. The normalized events are stored as RuntimeEvents and
// picked up unchanged by GET /v1/detection-validation.
//
// This is the posted-snapshot door (works today, no tsengine-side credential). The live pull — AWS
// WAFv2 GetSampledRequests, the Cloudflare firewall-events API — is the credential-gated half, the
// same shape as the OSINT / CloudTrail ingests.
func (d Deps) handleIngestControlDetections(w http.ResponseWriter, r *http.Request, tenantID string) {
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	switch source {
	case controltest.SourceAWSWAF, controltest.SourceCloudflare:
	default:
		writeJSON(w, http.StatusBadRequest, errBody("source must be aws_waf or cloudflare"))
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	// Accept one record or an array of them.
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		var one json.RawMessage
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			writeJSON(w, http.StatusBadRequest, errBody("body must be a WAF record or an array of them"))
			return
		}
		records = []json.RawMessage{one}
	}

	ctx := r.Context()
	canaries, err := d.tenantProbeCanaries(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}

	events, dropped := controltest.NormalizeWAF(source, records, canaries)
	now := time.Now().UTC()
	stored, matched, blocked := 0, 0, 0
	for _, ev := range events {
		ev.TenantID = tenantID // never trust a body-supplied tenant (isolation, §18.2 inv 2)
		ev.ID = d.newID("rte")
		if ev.OccurredAt.IsZero() {
			ev.OccurredAt = now
		}
		if err := d.Store.PutRuntimeEvent(ctx, ev); err != nil {
			respond(w, nil, err)
			return
		}
		stored++
		if ev.Marker != "" {
			matched++
		}
		if ev.Blocked {
			blocked++
		}
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("control-plane detections ingested", "control_test_ingest",
			map[string]any{"tenant_id": tenantID, "source": source, "stored": stored, "matched": matched},
			"WAF logs as the control under test")
	}
	// Echo what was PARSED, matched and dropped — so a caller whose payload used the wrong shape can
	// tell "the WAF saw nothing of ours" apart from "we did not understand your logs" (§10, the same
	// honesty the OSINT ingest echo enforces).
	writeJSON(w, http.StatusOK, map[string]any{
		"source":           source,
		"received":         len(records),
		"stored":           stored,
		"dropped":          dropped,
		"matched_to_probe": matched,
		"blocked":          blocked,
		"active_canaries":  len(canaries),
	})
}

// tenantProbeCanaries collects the canary tokens of every recorded probe across the tenant's
// engagements. These are the join keys a WAF log is matched against. An engagement with no attempts
// contributes nothing; a duplicate canary is de-duplicated.
func (d Deps) tenantProbeCanaries(ctx context.Context, tenantID string) ([]string, error) {
	engs, err := d.Store.ListPentests(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range engs {
		for _, a := range e.Attempts {
			c := strings.TrimSpace(a.Canary)
			if c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// tenantProbeMarkers is tenantProbeCanaries as a set, for excluding our own probes from the
// production-attack signal (crossdetect.WithoutOwnProbes).
func (d Deps) tenantProbeMarkers(ctx context.Context, tenantID string) (map[string]bool, error) {
	cs, err := d.tenantProbeCanaries(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, nil
	}
	m := make(map[string]bool, len(cs))
	for _, c := range cs {
		m[c] = true
	}
	return m, nil
}
