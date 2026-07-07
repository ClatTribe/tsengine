package grc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Continuous compliance evidence — the timeline half of GRC.
//
// EvidencePack (grc.go) is POINT-IN-TIME: it answers "is this control Met right now?". An auditor
// (SOC 2 Type II, ISO surveillance) needs the OTHER question: "was it Met across the whole window?".
// That needs a persisted history. CaptureEvidenceSnapshot appends a timestamped posture snapshot per
// framework to platform.ComplianceSnapshot (an APPEND-ONLY store timeline), and EvidenceTimeline reads it
// back with a continuity summary. Together they turn tsengine from "audit-ready today" into "audit-ready
// with the evidence to prove it held" — the Vanta/Drata continuous-monitoring bar.
//
// Grounded (§10): every count comes from a real Posture read; an empty posture captures nothing; and the
// "continuous" bit is stated honestly — it means every CAPTURED snapshot was fully met, NOT a guarantee
// about the gaps BETWEEN captures (which is why the capture cadence matters, below).

// stateHash is a stable fingerprint of a framework's per-control states, so an unchanged posture can be
// detected and a redundant capture skipped (change-detection, keeps the timeline meaningful not bloated).
func stateHash(cs []platform.ControlState) string {
	rows := make([]string, 0, len(cs))
	for _, c := range cs {
		rows = append(rows, c.ControlID+"="+c.State)
	}
	sort.Strings(rows)
	sum := sha256.Sum256([]byte(strings.Join(rows, ";")))
	return hex.EncodeToString(sum[:])
}

// CaptureEvidenceSnapshot appends a posture snapshot for a framework to the continuous-evidence timeline,
// but ONLY when the posture CHANGED since the tenant's latest snapshot for that framework, OR minInterval
// has elapsed (a periodic heartbeat proving the control still holds). captured=false means it was skipped
// (unchanged + within the interval) — so calling it every monitoring pass is cheap and the timeline
// doesn't bloat. minInterval<=0 forces a capture every call. Grounded: an empty/unassessed posture
// captures nothing (returns captured=false, no snapshot invented).
func (g *GRC) CaptureEvidenceSnapshot(ctx context.Context, tenantID, framework string, minInterval time.Duration) (platform.ComplianceSnapshot, bool, error) {
	cs, err := g.Posture(ctx, tenantID, framework)
	if err != nil {
		return platform.ComplianceSnapshot{}, false, err
	}
	if len(cs) == 0 {
		return platform.ComplianceSnapshot{}, false, nil // nothing assessed → nothing to attest to
	}
	met, gap := 0, 0
	for _, c := range cs {
		switch c.State {
		case platform.ControlMet:
			met++
		case platform.ControlGap:
			gap++
		}
	}
	hash := stateHash(cs)
	now := g.now()

	if prior, ok := g.latestSnapshot(ctx, tenantID, framework); ok {
		if prior.StateHash == hash && minInterval > 0 && now.Sub(prior.CapturedAt) < minInterval {
			return prior, false, nil // unchanged and within the heartbeat window → skip
		}
	}

	snap := platform.ComplianceSnapshot{
		ID:            framework + ":" + now.UTC().Format(time.RFC3339Nano),
		TenantID:      tenantID,
		Framework:     framework,
		CapturedAt:    now.UTC(),
		TotalControls: len(cs),
		MetControls:   met,
		GapControls:   gap,
		StateHash:     hash,
		FullyMet:      gap == 0,
	}
	if err := g.Store.PutComplianceSnapshot(ctx, snap); err != nil {
		return platform.ComplianceSnapshot{}, false, err
	}
	return snap, true, nil
}

// CaptureAllEvidence captures an evidence snapshot for every framework the tenant has ASSESSED (a
// framework with zero control state no-ops cheaply), returning how many were actually captured this call
// (skips don't count). This is the continuous-monitoring driver — the runner calls it each pass; the
// change+interval gate inside CaptureEvidenceSnapshot keeps it from bloating the timeline on a static
// estate. Best-effort per framework: one framework's error never blocks the rest.
func (g *GRC) CaptureAllEvidence(ctx context.Context, tenantID string, minInterval time.Duration) (int, error) {
	captured := 0
	var firstErr error
	for _, fw := range Frameworks {
		if _, ok, err := g.CaptureEvidenceSnapshot(ctx, tenantID, fw, minInterval); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else if ok {
			captured++
		}
	}
	return captured, firstErr
}

// latestSnapshot returns the most-recent snapshot for a (tenant, framework), ok=false if none exists.
func (g *GRC) latestSnapshot(ctx context.Context, tenantID, framework string) (platform.ComplianceSnapshot, bool) {
	all, err := g.Store.ListComplianceSnapshots(ctx, tenantID)
	if err != nil {
		return platform.ComplianceSnapshot{}, false
	}
	var latest platform.ComplianceSnapshot
	found := false
	for _, s := range all {
		if s.Framework != framework {
			continue
		}
		if !found || s.CapturedAt.After(latest.CapturedAt) {
			latest, found = s, true
		}
	}
	return latest, found
}

// EvidenceTimeline is the auditor-facing continuous-evidence view for one framework: the ordered
// snapshots (oldest→newest) plus a continuity summary over the captured window.
type EvidenceTimeline struct {
	Framework       string                        `json:"framework"`
	Snapshots       []platform.ComplianceSnapshot `json:"snapshots"`
	Count           int                           `json:"count"`
	FirstCapturedAt *time.Time                    `json:"first_captured_at,omitempty"`
	LastCapturedAt  *time.Time                    `json:"last_captured_at,omitempty"`
	// FullyMetRatio is the fraction of CAPTURED snapshots with zero gaps — the continuity metric. Honest
	// scope: it summarizes the captured points, not the gaps between them (so a denser cadence = stronger
	// evidence); it never claims the control held at un-sampled instants.
	FullyMetRatio float64 `json:"fully_met_ratio"`
	// Continuous is true when EVERY captured snapshot was fully met — "audit-ready across the sampled
	// window". Never asserted from a single snapshot's live state alone (that's the point-in-time pack).
	Continuous bool `json:"continuous"`
}

// EvidenceTimeline reads back the continuous-evidence history for a framework + its continuity summary.
func (g *GRC) EvidenceTimeline(ctx context.Context, tenantID, framework string) (EvidenceTimeline, error) {
	all, err := g.Store.ListComplianceSnapshots(ctx, tenantID)
	if err != nil {
		return EvidenceTimeline{}, err
	}
	snaps := make([]platform.ComplianceSnapshot, 0, len(all))
	for _, s := range all {
		if s.Framework == framework {
			snaps = append(snaps, s)
		}
	}
	// the store returns oldest-first, but re-sort defensively so the timeline order is guaranteed.
	sort.Slice(snaps, func(i, j int) bool {
		if snaps[i].CapturedAt.Equal(snaps[j].CapturedAt) {
			return snaps[i].ID < snaps[j].ID
		}
		return snaps[i].CapturedAt.Before(snaps[j].CapturedAt)
	})
	tl := EvidenceTimeline{Framework: framework, Snapshots: snaps, Count: len(snaps)}
	if len(snaps) == 0 {
		return tl, nil
	}
	fullyMet := 0
	for _, s := range snaps {
		if s.FullyMet {
			fullyMet++
		}
	}
	tl.FullyMetRatio = float64(fullyMet) / float64(len(snaps))
	tl.Continuous = fullyMet == len(snaps)
	first := snaps[0].CapturedAt
	last := snaps[len(snaps)-1].CapturedAt
	tl.FirstCapturedAt = &first
	tl.LastCapturedAt = &last
	return tl, nil
}
