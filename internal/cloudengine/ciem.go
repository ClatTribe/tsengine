package cloudengine

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/ciem"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ciem.go bridges the ciem rightsizing core to first-class cloud findings — the "end-to-end" half of
// CIEM (unused-permission / dormant-privilege detection, a Wiz/Orca capability). RightsizePrincipals
// reads each principal node's granted + used action sets from the snapshot and emits an over-privilege
// finding per over-granted principal, so CIEM flows through the same store / issues / GRC / HITL path as
// every other cloud finding.
//
// Grounding (§10, the honest gate lives in the ingest): a principal is assessed ONLY when its node
// carries observed usage data (Attrs["usage_observed"]=="true"). Absence of usage data → no claim. The
// granted side is Attrs["granted_actions"]; the usage side (Attrs["used_actions"] + window) is the gated
// live-ingest half — populated from CloudTrail / IAM last-accessed / Access Analyzer, or a posted
// inventory. Today's snapshots carry no such attrs, so this is inert until the ingest (or an operator
// snapshot) supplies them — the same core-first pattern as every ADR-0010 capability.

// principalUsageAttrs is the snapshot convention a principal node uses to feed CIEM.
const (
	attrGrantedActions  = "granted_actions"   // space/comma-separated granted actions (e.g. "iam:* s3:GetObject")
	attrUsedActions     = "used_actions"      // space/comma-separated actions observed in the window
	attrUsageWindowDays = "usage_window_days" // integer string
	attrUsageObserved   = "usage_observed"    // "true" → we actually have usage data (the honest gate)
)

// RightsizePrincipals returns an over-privilege finding for every principal in the snapshot whose granted
// permissions exceed what it used in the observation window. Deterministic; emits nothing when no
// principal carries observed usage data.
func RightsizePrincipals(snap *cloudgraph.Snapshot) []types.Finding {
	if snap == nil {
		return nil
	}
	var grants []ciem.Grant
	usage := map[string]ciem.Usage{}
	for id, n := range snap.Nodes {
		if n == nil || n.Kind != cloudgraph.KindPrincipal || n.Attrs == nil {
			continue
		}
		granted := splitActions(n.Attrs[attrGrantedActions])
		if len(granted) == 0 {
			continue
		}
		grants = append(grants, ciem.Grant{Principal: id, Actions: granted, Privileged: n.Privileged})
		if strings.EqualFold(strings.TrimSpace(n.Attrs[attrUsageObserved]), "true") {
			usage[id] = ciem.Usage{
				Actions:    splitActions(n.Attrs[attrUsedActions]),
				WindowDays: atoiSafe(n.Attrs[attrUsageWindowDays]),
				Observed:   true,
			}
		}
	}
	cf := ciem.Rightsize(grants, usage)
	out := make([]types.Finding, 0, len(cf))
	now := time.Now().UTC()
	for i, f := range cf {
		out = append(out, ciemToFinding(snap, i, f, now))
	}
	return out
}

func ciemToFinding(snap *cloudgraph.Snapshot, i int, f ciem.Finding, now time.Time) types.Finding {
	name := f.Principal
	if n := snap.Node(f.Principal); n != nil && n.Name != "" {
		name = n.Name
	}
	title := fmt.Sprintf("Over-privileged principal %s: %d unused permission(s)", name, len(f.UnusedActions))
	if len(f.UnusedActions) == 0 && len(f.OverbroadHints) > 0 {
		title = fmt.Sprintf("Over-broad wildcard grant on %s", name)
	}
	return types.Finding{
		ID:          fmt.Sprintf("ciem-%03d", i+1),
		RuleID:      "ciem::over-privileged-principal",
		Tool:        "ciem",
		Severity:    sevFromString(f.Severity),
		CWE:         []string{"CWE-250", "CWE-269"}, // unnecessary privileges / improper privilege management
		Endpoint:    f.Principal,
		Title:       title,
		Description: f.Recommendation,
		// least-privilege / access-management crosswalk (annotation-only, §8).
		Compliance: &types.Compliance{
			SOC2:      []string{"CC6.1", "CC6.3"},
			CISv8:     []string{"6.8"}, // define and maintain role-based access / least privilege
			NISTCSF:   []string{"PR.AA-05"},
			NIST80053: []string{"AC-6"}, // least privilege
			PCI:       []string{"7.2"},
			ISO27001:  []string{"A.8.2"}, // privileged access rights
		},
		DiscoveredAt: now,
	}
}

func sevFromString(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// splitActions parses a space/comma-separated action list, trimming blanks.
func splitActions(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(f))
	for _, x := range f {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
