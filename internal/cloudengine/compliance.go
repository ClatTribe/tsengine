package cloudengine

import (
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

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
	}
	if sensitive { // sensitive-data exposure / protection failure
		add(&c.SOC2, "CC6.1")
		add(&c.PCI, "3.4")
		add(&c.CISv8, "3.3")
		add(&c.NISTCSF, "PR.DS-1")
	}
	if privileged || privesc { // least-privilege failure
		add(&c.SOC2, "CC6.3")
		add(&c.PCI, "7.2")
		add(&c.CISv8, "5.4")
		add(&c.NISTCSF, "PR.AC-4")
	}
	if assume { // cross-identity lateral movement / access control
		add(&c.SOC2, "CC6.1")
		add(&c.CISv8, "6.8")
		add(&c.NISTCSF, "PR.AC-1")
	}

	if len(c.SOC2)+len(c.PCI)+len(c.CISv8)+len(c.NISTCSF) == 0 {
		return nil
	}
	return c
}
