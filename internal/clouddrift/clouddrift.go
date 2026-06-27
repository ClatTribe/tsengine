// Package clouddrift is CONTINUOUS DRIFT DETECTION over the cloud posture — the change-control half of the
// agentic-cloud-security category. It complements the two drift signals the platform already has:
//   - internal/cloudcdr   — AUDIT-LOG drift: catches a risky action the moment it appears in CloudTrail /
//     GCP Audit Logs / Azure Activity Log (needs the live event stream).
//   - internal/detect     — FINDING-diff drift: opens an incident when a NEW finding appears since the last scan.
//
// What neither does is CONFIG-SNAPSHOT-diff drift: compare two cloud inventory snapshots taken at different
// times and surface the security-relevant CONFIG CHANGES — a resource became public, a new privileged
// principal appeared, a new internet exposure / privilege-escalation / lateral-movement path opened — as
// deviation from an approved baseline, WITHOUT needing the audit-log stream. That's the SOC2/CIS change-
// control signal ("detect unauthorized changes to the environment"). Diff is the core.
//
// Deterministic + LLM-free + grounded (§10): every finding cites the exact node/edge that changed and the
// before→after; an unchanged pair of snapshots yields ZERO findings (drift isn't noise). The live half —
// persisting each tenant's last snapshot and diffing on every scan — is the platform wiring; Diff works
// today over any two posted snapshots (mirrors the OSINT/SaaS-posture ingest).
package clouddrift

import (
	"fmt"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Options tunes the diff; the zero value is sensible.
type Options struct {
	Now   func() time.Time
	NewID func() string
}

// Diff compares a baseline snapshot (prev) against the current one (cur) and returns grounded drift
// findings — the security-relevant config changes between them. prev==nil (no baseline yet) yields no
// findings: a first observation isn't drift.
func Diff(prev, cur *cloudgraph.Snapshot, opts Options) []types.Finding {
	if cur == nil || prev == nil {
		return nil
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}
	n := 0
	id := func() string {
		n++
		if opts.NewID != nil {
			return opts.NewID()
		}
		return fmt.Sprintf("drift-%d", n)
	}

	var out []types.Finding

	// --- node-level drift (matched by id) ---
	curIDs := make([]string, 0, len(cur.Nodes))
	for nid := range cur.Nodes {
		curIDs = append(curIDs, nid)
	}
	sort.Strings(curIDs)
	for _, nid := range curIDs {
		c := cur.Nodes[nid]
		p := prev.Nodes[nid]
		switch {
		case p == nil && c.Public:
			// a brand-new resource that is internet-exposed
			sev := types.SeverityMedium
			if c.Sensitive == cloudgraph.SensHigh || c.Privileged {
				sev = types.SeverityHigh
			}
			out = append(out, drift(id(), "clouddrift::new-public-resource", sev,
				"New internet-exposed resource appeared: "+label(c), nid,
				fmt.Sprintf("%s was not in the previous baseline and is internet-exposed per its config — an environment change that opened external attack surface. Confirm it was an authorized change.", label(c)),
				now))
		case p == nil && c.Privileged:
			out = append(out, drift(id(), "clouddrift::new-privileged-principal", types.SeverityHigh,
				"New privileged principal appeared: "+label(c), nid,
				fmt.Sprintf("%s is a high-privilege identity that was not in the previous baseline — a new admin-equivalent grant. Confirm it was an authorized change.", label(c)),
				now))
		case p != nil && !p.Public && c.Public:
			sev := types.SeverityHigh
			out = append(out, drift(id(), "clouddrift::resource-became-public", sev,
				"Resource became internet-exposed: "+label(c), nid,
				fmt.Sprintf("%s changed from NOT public to internet-exposed since the last baseline — a configuration change that opened external access. Verify this was intended.", label(c)),
				now))
		case p != nil && !p.Privileged && c.Privileged:
			out = append(out, drift(id(), "clouddrift::principal-became-privileged", types.SeverityHigh,
				"Principal was escalated to privileged: "+label(c), nid,
				fmt.Sprintf("%s changed from non-privileged to high-privilege since the last baseline — privilege creep / an unauthorized grant is a change-control concern.", label(c)),
				now))
		}
	}

	// --- edge-level drift (new risky edges, matched by from+to+kind) ---
	had := make(map[string]bool, len(prev.Edges))
	for _, e := range prev.Edges {
		had[edgeKey(e)] = true
	}
	for _, e := range cur.Edges {
		if had[edgeKey(e)] {
			continue // edge already existed in the baseline
		}
		switch e.Kind {
		case cloudgraph.EdgeNetworkReach:
			if e.From == cloudgraph.InternetID {
				out = append(out, drift(id(), "clouddrift::new-internet-exposure", types.SeverityHigh,
					"New internet reachability to "+label(cur.Node(e.To)), e.To,
					fmt.Sprintf("A new network path from the internet to %s appeared since the last baseline (a security-group / firewall opening) — new external attack surface.", label(cur.Node(e.To))),
					now))
			}
		case cloudgraph.EdgePrivesc:
			out = append(out, drift(id(), "clouddrift::new-privilege-escalation", types.SeverityHigh,
				"New privilege-escalation path from "+label(cur.Node(e.From)), e.From,
				fmt.Sprintf("%s gained a new privilege-escalation path (%s) since the last baseline.", label(cur.Node(e.From)), nz(e.Detail, "to admin")),
				now))
		case cloudgraph.EdgeSecretAccess:
			out = append(out, drift(id(), "clouddrift::new-lateral-movement", types.SeverityMedium,
				"New lateral-movement path from "+label(cur.Node(e.From)), e.From,
				fmt.Sprintf("%s gained a new secret-access lateral-movement path to %s since the last baseline.", label(cur.Node(e.From)), label(cur.Node(e.To))),
				now))
		}
	}
	return out
}

// drift builds a drift finding with the change-control compliance nexus (SOC2 CC8.1 change management +
// the access/config-monitoring controls a config change touches). Grounded — each cites the changed entity.
func drift(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "clouddrift", Severity: sev,
		Title: title, Endpoint: endpoint, Description: desc,
		DiscoveredAt:       now,
		VerificationStatus: types.VerificationVerified, // a config diff is a fact, not a heuristic
		Compliance: &types.Compliance{
			SOC2: []string{"CC8.1", "CC6.1", "CC7.1"}, CISv8: []string{"4.2", "8.5"},
			NISTCSF: []string{"PR.IP-1", "DE.CM-1"}, NIST80053: []string{"CM-3", "CM-6", "SI-4"},
			ISO27001: []string{"A.8.32"},
		},
	}
}

func edgeKey(e cloudgraph.Edge) string { return string(e.Kind) + "\x00" + e.From + "\x00" + e.To }

func label(n *cloudgraph.Node) string {
	if n == nil {
		return "(unknown)"
	}
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

func nz(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}
