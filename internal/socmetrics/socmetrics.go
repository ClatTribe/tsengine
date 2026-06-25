// Package socmetrics computes a tenant's security-operations performance from its incidents — the
// "how is the SOC performing" view a managed-security buyer expects (SLA compliance %, mean time to
// acknowledge / resolve, open-incident aging). Pure-compute + grounded (every number derives from
// real incident timestamps + the tenant's SLA policy); LLM-free, no side effects. The service-ops
// reporting half of the AAI-PO "24x7 SOC" expectation, sibling to internal/detect.
package socmetrics

import (
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Report is the operational scorecard over a tenant's incidents.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`

	OpenIncidents     int `json:"open_incidents"`
	ResolvedIncidents int `json:"resolved_incidents"`
	Acknowledged      int `json:"acknowledged"`  // open incidents a human has taken ownership of
	Unacknowledged    int `json:"unacknowledged"` // open incidents awaiting ownership

	// SLA compliance over SLA-tracked incidents (those whose severity has a target). Resolved
	// incidents count their HISTORICAL outcome (resolved within the window?); open incidents count
	// their CURRENT state (not yet breached?). Pct is 0 when nothing is tracked.
	SLATracked       int     `json:"sla_tracked"`
	SLACompliant     int     `json:"sla_compliant"`
	SLABreached      int     `json:"sla_breached"` // open incidents currently in breach
	SLACompliancePct float64 `json:"sla_compliance_pct"`

	MTTAHours float64 `json:"mtta_hours"` // mean open→acknowledge over acknowledged incidents
	MTTRHours float64 `json:"mttr_hours"` // mean open→resolve over resolved incidents

	// Aging of OPEN incidents by how long they've been open.
	AgingUnder1d int `json:"aging_under_1d"`
	Aging1to7d   int `json:"aging_1_7d"`
	AgingOver7d  int `json:"aging_over_7d"`
}

// Compute builds the report. sla may be nil (then no incident is SLA-tracked). now is injected so
// it is testable.
func Compute(incidents []platform.Incident, sla *platform.SLAPolicy, now time.Time) Report {
	r := Report{GeneratedAt: now}
	var ttaSum, ttrSum time.Duration
	var ttaN, ttrN int

	for _, inc := range incidents {
		resolved := inc.Status == platform.IncidentResolved
		if resolved {
			r.ResolvedIncidents++
			if !inc.OpenedAt.IsZero() && !inc.ResolvedAt.IsZero() && !inc.ResolvedAt.Before(inc.OpenedAt) {
				ttrSum += inc.ResolvedAt.Sub(inc.OpenedAt)
				ttrN++
			}
		} else {
			r.OpenIncidents++
			if inc.Acknowledged() {
				r.Acknowledged++
			} else {
				r.Unacknowledged++
			}
			r.bucketAge(inc, now)
		}
		if inc.Acknowledged() && !inc.OpenedAt.IsZero() && !inc.AcknowledgedAt.Before(inc.OpenedAt) {
			ttaSum += inc.AcknowledgedAt.Sub(inc.OpenedAt)
			ttaN++
		}

		// SLA compliance
		if tgt, ok := sla.TargetFor(inc.Severity); ok {
			r.SLATracked++
			if slaCompliant(inc, tgt, sla, now) {
				r.SLACompliant++
			}
			if !resolved {
				if b, ok := sla.Evaluate(inc, now); ok && b.Breached() {
					r.SLABreached++
				}
			}
		}
	}

	if r.SLATracked > 0 {
		r.SLACompliancePct = round1(float64(r.SLACompliant) / float64(r.SLATracked) * 100)
	}
	if ttaN > 0 {
		r.MTTAHours = round1(ttaSum.Hours() / float64(ttaN))
	}
	if ttrN > 0 {
		r.MTTRHours = round1(ttrSum.Hours() / float64(ttrN))
	}
	return r
}

// slaCompliant: a resolved incident is compliant if it was resolved within its resolve window
// (historical truth); an open incident is compliant if it is not currently breached.
func slaCompliant(inc platform.Incident, tgt platform.SLATarget, sla *platform.SLAPolicy, now time.Time) bool {
	if inc.Status == platform.IncidentResolved {
		if tgt.ResolveHours <= 0 || inc.OpenedAt.IsZero() || inc.ResolvedAt.IsZero() {
			return true // no resolve clock or missing timestamps → not counted as a miss
		}
		window := time.Duration(tgt.ResolveHours) * time.Hour
		return inc.ResolvedAt.Sub(inc.OpenedAt) <= window
	}
	b, ok := sla.Evaluate(inc, now)
	return !ok || !b.Breached()
}

func (r *Report) bucketAge(inc platform.Incident, now time.Time) {
	if inc.OpenedAt.IsZero() {
		return
	}
	age := now.Sub(inc.OpenedAt)
	switch {
	case age < 24*time.Hour:
		r.AgingUnder1d++
	case age < 7*24*time.Hour:
		r.Aging1to7d++
	default:
		r.AgingOver7d++
	}
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
