package cloudengine

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// IssueCompliance maps an agent-recorded attack path (its ARN node list + target) to the compliance
// controls it violates, by reconstructing the path's REAL edges from the snapshot and reusing
// pathCompliance (§8 emission-path 3). This closes the gap where the AI Cloud Engineer's OWN findings
// (cloudagent.Issue, which carry only a []string node list) bypassed the deterministic attack-path
// compliance mapping every engine-discovered path already gets. Grounded (§10): only edges that
// actually exist in the snapshot contribute, and the target's sensitivity/privilege come from the real
// node — returns nil when the path is empty or no characteristic maps, never an over-claim.
func IssueCompliance(snap *cloudgraph.Snapshot, nodes []string, target string) *types.Compliance {
	if snap == nil || len(nodes) == 0 {
		return nil
	}
	var edges []cloudgraph.Edge
	for i := 0; i+1 < len(nodes); i++ {
		for _, e := range snap.Edges {
			if e.From == nodes[i] && e.To == nodes[i+1] {
				edges = append(edges, e)
			}
		}
	}
	var tn *cloudgraph.Node
	if strings.TrimSpace(target) != "" {
		tn = snap.Node(target)
	}
	return pathCompliance(cloudgraph.Path{Nodes: nodes, Edges: edges}, tn)
}

// pathCompliance maps an attack path to the compliance controls it violates —
// the compliance-auditor lens of the dual-view (CLAUDE.md §8). Honest-mapping
// discipline: only controls defensibly tied to a path characteristic are
// emitted (internet exposure, sensitive-data access, privilege escalation,
// cross-identity lateral movement); nothing is over-claimed. Returns nil when
// no characteristic applies.
func pathCompliance(p cloudgraph.Path, target *cloudgraph.Node) *types.Compliance {
	var publicReach, assume, privesc bool
	for _, e := range p.Edges {
		switch e.Kind {
		case cloudgraph.EdgeNetworkReach:
			if e.From == cloudgraph.InternetID {
				publicReach = true
			}
		case cloudgraph.EdgeAssumeRole, cloudgraph.EdgePassRole:
			assume = true
		case cloudgraph.EdgePrivesc:
			privesc = true
		}
	}
	sensitive := target != nil && target.Sensitive == cloudgraph.SensHigh
	privileged := target != nil && target.Privileged

	c := &types.Compliance{}
	add := func(dst *[]string, vals ...string) {
		for _, v := range vals {
			*dst = appendUnique(*dst, v)
		}
	}

	if publicReach { // internet-exposed boundary / segmentation failure
		add(&c.SOC2, "CC6.6")
		add(&c.PCI, "1.3")
		add(&c.CISv8, "13.4")
		add(&c.NISTCSF, "PR.AC-5")
		add(&c.GDPR, "Art. 32")
		add(&c.NIST80053, "SC-7", "AC-4")
		add(&c.NIST800171, "3.13.1", "3.1.3")
		add(&c.FedRAMP, "SC-7", "AC-4")
		add(&c.DPDP, "Sec. 8(5)")
		add(&c.HIPAA, "164.312(e)(1)")
		add(&c.ISO27001, "A.8.20", "A.8.22")
	}
	if sensitive { // sensitive-data exposure / protection failure
		add(&c.SOC2, "CC6.1")
		add(&c.PCI, "3.4")
		add(&c.CISv8, "3.3")
		add(&c.NISTCSF, "PR.DS-1")
		add(&c.GDPR, "Art. 32", "Art. 5(1)(f)")
		add(&c.ISO27701, "6.11")
		add(&c.NIST80053, "SC-28", "SC-8")
		add(&c.NIST800171, "3.13.16", "3.13.8")
		add(&c.CCPA, "1798.150", "1798.100")
		add(&c.FedRAMP, "SC-28", "SC-8")
		add(&c.DPDP, "Sec. 8(5)")
		add(&c.HIPAA, "164.312(a)(1)", "164.312(e)(1)")
		add(&c.ISO27001, "A.8.12")
		add(&c.SOX, "ITGC: Access to Programs & Data")
	}
	if privileged || privesc { // least-privilege failure
		add(&c.SOC2, "CC6.3")
		add(&c.PCI, "7.2")
		add(&c.CISv8, "5.4")
		add(&c.NISTCSF, "PR.AC-4")
		add(&c.GDPR, "Art. 32")
		add(&c.NIST80053, "AC-6")
		add(&c.NIST800171, "3.1.5")
		add(&c.FedRAMP, "AC-6")
		add(&c.DPDP, "Sec. 8(5)")
		add(&c.HIPAA, "164.312(a)(1)")
		add(&c.ISO27001, "A.8.2")
		add(&c.SOX, "ITGC: Access to Programs & Data")
	}
	if assume { // cross-identity lateral movement / access control
		add(&c.SOC2, "CC6.1")
		add(&c.CISv8, "6.8")
		add(&c.NISTCSF, "PR.AC-1")
		add(&c.GDPR, "Art. 32")
		add(&c.NIST80053, "AC-3", "AC-4")
		add(&c.NIST800171, "3.1.3")
		add(&c.FedRAMP, "AC-3", "AC-4")
		add(&c.DPDP, "Sec. 8(5)")
		add(&c.HIPAA, "164.312(a)(1)")
		add(&c.ISO27001, "A.5.15")
		add(&c.SOX, "ITGC: Access to Programs & Data")
	}

	if len(c.SOC2)+len(c.PCI)+len(c.CISv8)+len(c.NISTCSF)+len(c.GDPR)+len(c.NIST80053)+
		len(c.NIST800171)+len(c.CCPA)+len(c.FedRAMP)+len(c.DPDP)+len(c.ISO27701)+
		len(c.HIPAA)+len(c.ISO27001)+len(c.SOX) == 0 {
		return nil
	}
	return c
}
