// Package offensivecontext is the ONE shared provider of ADR-0019 offensive-face exploit context
// for both offensive agents (ADR 0021 migration step 1). It resolves a finding to the rendered
// request skeleton known to trigger its CVE — the material the model ADAPTS in its PROPOSE step.
//
// WHY A SEPARATE PACKAGE. internal/pentest deliberately stays free of the corpus package (see
// pentest/exploitintel.go's LAYERING note): it declares only the func-var seam + CVEOf. webagent
// likewise stays corpus-free (its seam is a func value too). So neither agent can own the resolver
// that joins pentest.CVEOf to the threat-intel sidecar. This package is that join, imported by the
// wiring layers (platformapi, cmd/tsengine's web-investigate) so the two agents read the SAME
// resolver and cannot drift — the drift the ADR calls out.
//
// Grounded (§10): a resolver returns "" for any finding that does not name a CVE with a real record,
// so it is input to the PROPOSE step only; the deterministic predicate/indicator still disposes.
package offensivecontext

import (
	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Resolver builds the finding→offensive-context function over a record set. Pure + unit-testable, no
// install/reload machinery. Empty record set → a resolver that always returns "" (never nil, so a
// caller can install it unconditionally).
func Resolver(records map[string]threatintel.ExploitRecord) func(types.Finding) string {
	return func(f types.Finding) string {
		cve := pentest.CVEOf(f)
		if cve == "" {
			return "" // grounded: only a CVE-bearing finding can have an offensive record
		}
		rec, ok := records[cve]
		if !ok {
			return ""
		}
		return threatintel.RenderExploitContext(rec)
	}
}

// Load reads the exploit-intel sidecar from a corpus dir and returns a grounded resolver over it, plus
// ok=false when no sidecar is present (the honest no-intel path — the caller then leaves the agent's
// hook nil and the prompt is byte-identical to today). A one-shot load for CLI/bench callers; the
// live modtime-watching reload lives in the platform's long-running install layer.
func Load(dir string) (func(types.Finding) string, bool) {
	recs, found, err := threatintel.LoadExploitIntel(dir)
	if err != nil || !found {
		return nil, false
	}
	return Resolver(recs), true
}
