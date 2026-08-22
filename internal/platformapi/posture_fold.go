package platformapi

import (
	"context"
	"log/slog"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// foldIntoPosture applies a stored finding to the compliance system-of-record, and REPORTS what it
// could not apply.
//
// Every ingest door discarded the error from this call — SIXTEEN of them, identically — while the scan door
// treats the same call as FATAL (runner.processFinding returns the error and aborts). The same
// operation cannot be load-bearing on one door and ignorable on eight.
//
// What a dropped Apply costs is the failure mode the compliance layer exists to prevent: the finding
// is stored and visible, and the control gap it should have opened never opens. The posture then
// shows no gap for a real finding — false compliant, arriving through the ingest door rather than
// through reconciliation.
//
// It stays NON-FATAL, deliberately: the findings are already persisted by this point, so returning
// 500 would tell the caller their ingest failed when the part they care about succeeded, and a
// retry would duplicate it. But non-fatal is not the same as invisible, and it was invisible.
func (d Deps) foldIntoPosture(ctx context.Context, tenantID string, findings []types.Finding) int {
	if d.GRC == nil {
		return 0
	}
	failed := 0
	for _, f := range findings {
		if err := d.GRC.Apply(ctx, tenantID, f); err != nil {
			failed++
			slog.Warn("[posture] finding stored but NOT folded into compliance posture — the control "+
				"gap it should open will not appear",
				"tenant", tenantID, "finding", f.ID, "rule", f.RuleID, "err", err.Error())
		}
	}
	return failed
}
