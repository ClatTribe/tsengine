// Package bizservice answers the CTEM scoping question the product could not: WHICH BUSINESS
// SERVICE does this exposure threaten?
//
// ADR 0028 G2. Scoping in CTEM means mapping critical business services to the assets that carry
// them. The product had DataTier per asset, which is a decent crown-jewel proxy and is not the same
// thing: "this repository is tier 1" does not say that CHECKOUT depends on it, and it is the service
// that has an owner, a revenue number and someone who will be paged.
//
// # What this is and is not
//
// It is a GROUPING over data that already exists — services declared by the customer, assets already
// discovered, findings already attributed. It adds no detection and asserts no new fact about
// security (§13 holds).
//
// # The refusals, which are most of the value
//
//   - AN ASSET IN A SERVICE THAT WAS NEVER SCANNED IS REPORTED, NOT COUNTED CLEAN. A service whose
//     three assets include one nobody scanned is not a service with a clean bill of health, and the
//     difference between "we looked and found nothing" and "we did not look" is the distinction this
//     whole codebase is built around.
//   - ATTRIBUTION IS LITERAL, NEVER FUZZY. A finding belongs to an asset only when that asset's
//     target really appears in the finding's endpoint, longest match wins — the same rule
//     crossdetect.PrioritizeByDataTier and the per-asset compliance view already use. A guessed
//     service attribution would send the wrong team to the wrong incident, which is worse than no
//     attribution.
//   - FINDINGS THAT MAP TO NO SERVICE ARE COUNTED AND SURFACED. Otherwise declaring one service makes
//     the rest of the estate disappear from the view, and a partial map reads as a complete one.
package bizservice

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ServiceExposure is one business service's security state.
type ServiceExposure struct {
	ServiceID   string `json:"service_id"`
	Name        string `json:"name"`
	Criticality string `json:"criticality,omitempty"`
	Owner       string `json:"owner,omitempty"`

	// Assets is how many assets carry this service, and Scanned how many of those have actually been
	// assessed. A service is only as assessed as its least-assessed asset.
	Assets  int `json:"assets"`
	Scanned int `json:"scanned"`
	// UnscannedTargets names the assets nobody has assessed, because a count does not tell an owner
	// which part of their service is dark.
	UnscannedTargets []string `json:"unscanned_targets,omitempty"`

	Findings      int            `json:"findings"`
	BySeverity    map[string]int `json:"by_severity,omitempty"`
	WorstSeverity string         `json:"worst_severity,omitempty"`
	// Exploited counts findings that reached the strongest evidence rung — an attack that ran. The
	// number an owner acts on first.
	Exploited int `json:"exploited"`

	// Assessed is false when NO asset in this service has been scanned. Then the finding count is
	// zero for the uninteresting reason and must not read as a clean service.
	Assessed bool `json:"assessed"`
	// Note states the limit in words when there is one.
	Note string `json:"note,omitempty"`
}

// Report is every declared service plus what fell outside all of them.
type Report struct {
	Services []ServiceExposure `json:"services"`
	// Unmapped counts findings that attribute to no declared service — either the asset is in no
	// service, or the finding attributes to no asset at all (a repository file:line endpoint, for
	// instance, which no asset target matches).
	Unmapped int `json:"unmapped_findings"`
	// UnmappedNote explains that count rather than leaving a bare number that reads as an error.
	UnmappedNote string `json:"unmapped_note,omitempty"`
	// Declared is false when the customer has mapped no services. The whole view is then a prompt
	// rather than a report, and says so.
	Declared bool   `json:"declared"`
	Note     string `json:"note,omitempty"`
}

// Compute groups findings by declared business service.
//
// scannedAssetIDs is the set of assets an assessment has actually run against — supplied by the
// caller because that comes from engagement history, which this package deliberately does not read.
func Compute(services []platform.BusinessService, assets []platform.Asset, findings []types.Finding, scannedAssetIDs map[string]bool) Report {
	rep := Report{Declared: len(services) > 0}
	if !rep.Declared {
		rep.Note = "No business services are mapped, so exposure cannot be grouped by what it threatens. " +
			"Map a service to the assets that carry it — the question an owner asks is not \"is this repo " +
			"risky\" but \"is checkout at risk\"."
		return rep
	}

	byID := make(map[string]platform.Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}

	// Attribute each finding to at most one asset: literal target match, longest wins. Same rule as
	// the data-tier and per-asset compliance views, so the three never disagree about ownership.
	assetOf := make(map[string]string, len(findings)) // finding ID -> asset ID
	for _, f := range findings {
		best, bestLen := "", 0
		for _, a := range assets {
			t := strings.TrimSpace(a.Target)
			if t == "" || !strings.Contains(f.Endpoint, t) {
				continue
			}
			if len(t) > bestLen {
				best, bestLen = a.ID, len(t)
			}
		}
		if best != "" {
			assetOf[f.ID] = best
		}
	}

	claimed := map[string]bool{} // finding IDs claimed by some service
	for _, svc := range services {
		se := ServiceExposure{
			ServiceID: svc.ID, Name: svc.Name, Criticality: svc.Criticality, Owner: svc.Owner,
			BySeverity: map[string]int{},
		}
		inService := map[string]bool{}
		for _, id := range svc.AssetIDs {
			a, ok := byID[id]
			if !ok {
				continue // an asset that no longer exists is not evidence of anything
			}
			inService[id] = true
			se.Assets++
			if scannedAssetIDs[id] {
				se.Scanned++
			} else {
				se.UnscannedTargets = append(se.UnscannedTargets, a.Target)
			}
		}
		for _, f := range findings {
			if aid, ok := assetOf[f.ID]; !ok || !inService[aid] {
				continue
			}
			claimed[f.ID] = true
			se.Findings++
			sev := strings.ToLower(string(f.Severity))
			se.BySeverity[sev]++
			if worseSeverity(sev, se.WorstSeverity) {
				se.WorstSeverity = sev
			}
			if f.DeriveRung().ClaimsExploitability() {
				se.Exploited++
			}
		}
		se.Assessed = se.Scanned > 0
		switch {
		case se.Assets == 0:
			se.Note = "No assets are mapped to this service, so nothing here describes its security."
		case !se.Assessed:
			se.Note = "None of this service's assets has been assessed yet. A zero here means nobody has " +
				"looked, not that nothing was found."
		case len(se.UnscannedTargets) > 0:
			se.Note = "Partly assessed: " + plural(len(se.UnscannedTargets)) +
				" carrying this service has not been scanned, so this is not a complete picture of it."
		}
		rep.Services = append(rep.Services, se)
	}

	for _, f := range findings {
		if !claimed[f.ID] {
			rep.Unmapped++
		}
	}
	if rep.Unmapped > 0 {
		rep.UnmappedNote = "These findings belong to no mapped service — their asset is in no service, or " +
			"the finding's location matches no asset target (a source file:line, for example). They are " +
			"real and they are not represented above."
	}
	sort.SliceStable(rep.Services, func(i, j int) bool {
		return critRank(rep.Services[i].Criticality) > critRank(rep.Services[j].Criticality)
	})
	return rep
}

func plural(n int) string {
	if n == 1 {
		return "1 asset"
	}
	return itoa(n) + " assets"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

func worseSeverity(a, b string) bool { return sevRank[a] > sevRank[b] }

var critOrder = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

func critRank(c string) int { return critOrder[strings.ToLower(strings.TrimSpace(c))] }
