package common

import (
	"time"

	"github.com/ClatTribe/tsengine/internal/supplychain"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// SupplyChainFindings runs the dependency-set risk checks over any CycloneDX
// SBOM present in the tool results (syft emits one on the repository + container
// assets). It is the host-side wiring for internal/supplychain: the SBOM gives
// the resolved dependency set, which is checked for (1) MALICIOUS packages
// (corpus match — hostile by design, usually no CVE) and (2) END-OF-LIFE
// runtimes/frameworks (past their published EOL date — unpatched and growing).
// Both are distinct from the SCA tools' CVE findings.
//
// Tool-agnostic (content-detects the SBOM) and a no-op when no SBOM is present,
// so callers can append it unconditionally.
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
	now := time.Now()
	out := supplychain.Scan(pkgs, supplychain.DefaultCorpus(), supplychain.Options{})
	out = append(out, supplychain.ScanEOL(pkgs, supplychain.DefaultEOLCorpus(), now)...)
	out = append(out, supplychain.ScanDeprecated(pkgs, supplychain.DefaultDeprecatedCorpus(), now)...)
	return out
}
