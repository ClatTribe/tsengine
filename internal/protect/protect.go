// Package protect is the /Protect runtime-security surface (Aikido /Protect parity) — a posture roll-up over
// the in-app-firewall / RASP block events the platform already ingests (platform.RuntimeEvent, fed by an
// OSS sensor like Zen; ADR-0007 Phase 0). tsengine does NOT block in production — the customer's installed
// sensor does (§13: consume the OSS signal, never build a RASP). This package turns that ingested signal
// into a first-class "is my runtime protected, and what is it stopping?" view: which apps are reporting,
// how many attacks were blocked vs only monitored, the top attack types and most-targeted endpoints.
//
// Grounded (§10): every number comes from real ingested events. No events → Active:false ("no runtime
// signal yet"), never "protected". A monitor-only deployment (nothing blocked) reports honestly as active
// but BlockRate 0 — monitoring, not blocking.
package protect

import (
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Status is the runtime-protection posture.
type Status struct {
	Active       bool            `json:"active"`  // a sensor is reporting events (protection is live)
	Apps         []string        `json:"apps"`    // apps that reported runtime events
	Sensors      []string        `json:"sensors"` // sensor sources (e.g. "zen")
	TotalAttacks int             `json:"total_attacks"`
	Blocked      int             `json:"blocked"`        // attacks the sensor blocked
	MonitorOnly  int             `json:"monitor_only"`   // observed but not blocked (monitor mode / unprotected route)
	BlockRate    float64         `json:"block_rate"`     // blocked / total, 0..1 (0 ⇒ monitoring, not blocking)
	ByAttackKind []KindCount     `json:"by_attack_kind"` // most frequent first
	TopEndpoints []EndpointCount `json:"top_endpoints"`  // most-targeted first, capped
	Since        time.Time       `json:"since,omitempty"`
}

type KindCount struct {
	Kind    string `json:"kind"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
}
type EndpointCount struct {
	Endpoint string `json:"endpoint"`
	Count    int    `json:"count"`
	Blocked  int    `json:"blocked"`
}

// Compute rolls up the runtime-protection posture from the ingested events. Events older than `since` are
// ignored (zero `since` ⇒ all events). topN caps TopEndpoints (≤0 ⇒ default 10).
func Compute(events []platform.RuntimeEvent, since time.Time, topN int) Status {
	if topN <= 0 {
		topN = 10
	}
	st := Status{Since: since}
	apps := map[string]bool{}
	sensors := map[string]bool{}
	kinds := map[string]*KindCount{}
	endpoints := map[string]*EndpointCount{}

	for _, e := range events {
		if !since.IsZero() && e.OccurredAt.Before(since) {
			continue
		}
		st.Active = true // a real event means a sensor is live
		if e.App != "" {
			apps[e.App] = true
		}
		if e.Source != "" {
			sensors[e.Source] = true
		}
		st.TotalAttacks++
		if e.Blocked {
			st.Blocked++
		} else {
			st.MonitorOnly++
		}
		if k := e.AttackKind; k != "" {
			kc := kinds[k]
			if kc == nil {
				kc = &KindCount{Kind: k}
				kinds[k] = kc
			}
			kc.Count++
			if e.Blocked {
				kc.Blocked++
			}
		}
		if ep := e.Endpoint; ep != "" {
			ec := endpoints[ep]
			if ec == nil {
				ec = &EndpointCount{Endpoint: ep}
				endpoints[ep] = ec
			}
			ec.Count++
			if e.Blocked {
				ec.Blocked++
			}
		}
	}

	st.Apps = sortedKeys(apps)
	st.Sensors = sortedKeys(sensors)
	if st.TotalAttacks > 0 {
		st.BlockRate = float64(st.Blocked) / float64(st.TotalAttacks)
	}
	for _, kc := range kinds {
		st.ByAttackKind = append(st.ByAttackKind, *kc)
	}
	sort.Slice(st.ByAttackKind, func(i, j int) bool {
		if st.ByAttackKind[i].Count != st.ByAttackKind[j].Count {
			return st.ByAttackKind[i].Count > st.ByAttackKind[j].Count
		}
		return st.ByAttackKind[i].Kind < st.ByAttackKind[j].Kind
	})
	for _, ec := range endpoints {
		st.TopEndpoints = append(st.TopEndpoints, *ec)
	}
	sort.Slice(st.TopEndpoints, func(i, j int) bool {
		if st.TopEndpoints[i].Count != st.TopEndpoints[j].Count {
			return st.TopEndpoints[i].Count > st.TopEndpoints[j].Count
		}
		return st.TopEndpoints[i].Endpoint < st.TopEndpoints[j].Endpoint
	})
	if len(st.TopEndpoints) > topN {
		st.TopEndpoints = st.TopEndpoints[:topN]
	}
	return st
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
