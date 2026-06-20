package common

import (
	"github.com/ClatTribe/tsengine/internal/supplychain"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// SupplyChainFindings runs malicious-package detection over any CycloneDX SBOM
// present in the tool results (syft emits one on the repository + container
// assets). It is the host-side wiring for internal/supplychain: the SBOM gives
// the resolved dependency set, which is matched against the known-malicious
// corpus. Tool-agnostic (content-detects the SBOM) and a no-op when no SBOM is
// present, so callers can append it unconditionally.
//
// These findings are distinct from the SCA tools' CVE findings: a malicious
// package is hostile by design and usually carries no CVE.
func SupplyChainFindings(results []tool.Result) []types.Finding {
	var pkgs []supplychain.Package
	seen := map[string]bool{}
	for _, r := range results {
		for _, p := range supplychain.PackagesFromSBOM(r.Output) {
			k := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) == 0 {
		return nil
	}
	return supplychain.Scan(pkgs, supplychain.DefaultCorpus(), supplychain.Options{})
}
